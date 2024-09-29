use clap::{arg, Parser};
use erofs_sys::data::backends::uncompressed::UncompressedBackend;
use erofs_sys::data::*;
use erofs_sys::errnos::Errno::*;
use erofs_sys::file::ImageFileSystem;
use erofs_sys::inode::*;
use erofs_sys::operations::*;
use erofs_sys::superblock::FileSystem as ErofsFileSystem;
use erofs_sys::superblock::SuperBlock;
use erofs_sys::xattrs::*;
use erofs_sys::{Nid, Off, PosixResult};
use fuser::Filesystem as FuseFileSystem;
use fuser::MountOption;
use fuser::{
    FileAttr, FileType, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, Request, FUSE_ROOT_ID,
};
use std::collections::{hash_map::Entry, HashMap};
use std::ffi::OsStr;
use std::ffi::*;
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

struct FuseCollection(HashMap<Nid, SimpleInode>);
struct FuseFile(File);

impl Source for FuseFile {
    fn fill(&self, data: &mut [u8], _device_id: i32, offset: Off) -> PosixResult<u64> {
        self.0
            .read_at(data, offset)
            .map_or(Err(ERANGE), |size| Ok(size as u64))
    }
}

impl FileSource for FuseFile {}

struct SimpleInode {
    info: InodeInfo,
    xattr_shared_entries: XAttrSharedEntries,
    nid: Nid,
}

impl Inode for SimpleInode {
    fn new(_sb: &SuperBlock, info: InodeInfo, nid: Nid, xattr_header: XAttrSharedEntries) -> Self {
        Self {
            info,
            xattr_shared_entries: xattr_header,
            nid,
        }
    }
    fn xattrs_shared_entries(&self) -> &XAttrSharedEntries {
        &self.xattr_shared_entries
    }
    fn nid(&self) -> Nid {
        self.nid
    }
    fn info(&self) -> &InodeInfo {
        &self.info
    }
}

impl InodeCollection for FuseCollection {
    type I = SimpleInode;
    fn iget(&mut self, nid: Nid, f: &dyn ErofsFileSystem<Self::I>) -> PosixResult<&mut Self::I> {
        match self.0.entry(nid) {
            Entry::Vacant(v) => {
                let info = f.read_inode_info(nid)?;
                let xattrs_header = f.read_inode_xattrs_shared_entries(nid, &info)?;
                Ok(v.insert(Self::I::new(f.superblock(), info, nid, xattrs_header)))
            }
            Entry::Occupied(o) => Ok(o.into_mut()),
        }
    }
    fn release(&mut self, nid: Nid) {
        self.0.remove(&nid);
    }
}

struct ErofsFuse {
    filesystem: Box<dyn ErofsFileSystem<SimpleInode>>,
    collection: FuseCollection,
}

fn system_time_from_time(secs: i64, nsecs: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::new(secs as u64, nsecs)
    } else {
        UNIX_EPOCH - Duration::new((-secs) as u64, nsecs)
    }
}

fn file_type_from_type(ty: Type) -> FileType {
    match ty {
        Type::Regular => FileType::RegularFile,
        Type::Directory => FileType::Directory,
        Type::Link => FileType::Symlink,
        Type::Fifo => FileType::NamedPipe,
        Type::Character => FileType::CharDevice,
        Type::Block => FileType::BlockDevice,
        Type::Socket => FileType::Socket,
        Type::Unknown => panic!("Unknown Type"),
    }
}

fn get_file_attr_from_filesystem_inode(inode: &SimpleInode, sb: &SuperBlock) -> FileAttr {
    match *inode.info() {
        InodeInfo::Extended(e) => FileAttr {
            atime: system_time_from_time(e.i_mtime as i64, e.i_mtime_nsec),
            ino: inode.nid() + FUSE_ROOT_ID,
            size: e.i_size,
            blocks: sb.blk_round_up_generic(e.i_size) as u64,
            mtime: system_time_from_time(e.i_mtime as i64, e.i_mtime_nsec),
            ctime: system_time_from_time(e.i_mtime as i64, e.i_mtime_nsec),
            crtime: system_time_from_time(e.i_mtime as i64, e.i_mtime_nsec),
            perm: inode.info().inode_perm(),
            kind: file_type_from_type(inode.info().inode_type()),
            nlink: e.i_nlink,
            blksize: 512,
            uid: e.i_uid,
            gid: e.i_gid,
            rdev: 0,
            flags: 0,
        },
        InodeInfo::Compact(c) => FileAttr {
            atime: system_time_from_time(sb.build_time, sb.build_time_nsec as u32),
            ino: inode.nid() + FUSE_ROOT_ID,
            size: c.i_size as u64,
            blocks: sb.blk_round_up_generic(c.i_size as u64) as u64,
            mtime: system_time_from_time(sb.build_time, sb.build_time_nsec as u32),
            ctime: system_time_from_time(sb.build_time, sb.build_time_nsec as u32),
            crtime: system_time_from_time(sb.build_time, sb.build_time_nsec as u32),
            perm: inode.info().inode_perm(),
            kind: file_type_from_type(inode.info().inode_type()),
            nlink: c.i_nlink as u32,
            blksize: 512,
            uid: c.i_uid as u32,
            gid: c.i_gid as u32,
            rdev: 0,
            flags: 0,
        },
    }
}

fn filetype_from_dtype(ty: u8) -> FileType {
    match ty {
        1 => FileType::RegularFile,
        2 => FileType::Directory,
        3 => FileType::CharDevice,
        4 => FileType::BlockDevice,
        5 => FileType::NamedPipe,
        6 => FileType::Socket,
        7 => FileType::Symlink,
        _ => panic!("unknown"),
    }
}

fn nid_to_ino(sb: &SuperBlock, nid: Nid) -> u64 {
    if nid == sb.root_nid as u64 {
        FUSE_ROOT_ID
    } else {
        nid + FUSE_ROOT_ID
    }
}
impl ErofsFuse {
    fn ino_to_nid(&self, ino: u64) -> Nid {
        if ino == FUSE_ROOT_ID {
            self.filesystem.superblock().root_nid as u64
        } else {
            ino - FUSE_ROOT_ID
        }
    }
    fn try_read_link(&mut self, ino: u64) -> PosixResult<Vec<u8>> {
        let inode = self
            .collection
            .iget(self.ino_to_nid(ino), self.filesystem.as_filesystem())?;
        let mut symlink: Vec<u8> = Vec::new();
        for res in self.filesystem.mapped_iter(inode, 0)? {
            let block = res?;
            let data = block.content();
            symlink.extend_from_slice(data);
        }
        symlink.push(b'\0');
        Ok(symlink)
    }
    fn try_read(&mut self, ino: u64, offset: i64, mut size: u32) -> PosixResult<Vec<u8>> {
        let inode = self
            .collection
            .iget(self.ino_to_nid(ino), self.filesystem.as_filesystem())?;
        let mut result: Vec<u8> = Vec::new();
        for res in self.filesystem.mapped_iter(inode, offset as u64)? {
            let block = res?;
            let data = block.content();
            let nsize = data.len().min(size as usize);
            result.extend_from_slice(&data[..nsize]);
            size -= nsize as u32;
            if size == 0 {
                break;
            }
        }
        Ok(result)
    }
}
const TTL: Duration = Duration::from_secs(1); // 1 second
impl FuseFileSystem for ErofsFuse {
    fn init(&mut self, _req: &Request<'_>, _config: &mut fuser::KernelConfig) -> Result<(), c_int> {
        Ok(())
    }
    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let sb = self.filesystem.superblock();
        match self
            .collection
            .iget(self.ino_to_nid(ino), self.filesystem.as_filesystem())
        {
            Ok(inode) => {
                let mut count = 1;
                match self
                    .filesystem
                    .fill_dentries(inode, 0, offset as u64, &mut |dirent, _| {
                        if reply.add(
                            nid_to_ino(sb, dirent.desc().nid),
                            count + 1,
                            filetype_from_dtype(dirent.desc().file_type),
                            OsStr::from_bytes(dirent.dirname()),
                        ) {
                            true
                        } else {
                            count += 1;
                            false
                        }
                    }) {
                    Ok(()) => reply.ok(),
                    Err(e) => reply.error(e as i32),
                }
            }
            Err(e) => reply.error(e as i32),
        }
    }
    fn lookup(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        _name: &std::ffi::OsStr,
        reply: ReplyEntry,
    ) {
        let nid = self.ino_to_nid(parent);
        match lookup(
            self.filesystem.as_filesystem(),
            &mut self.collection,
            nid,
            _name.to_str().unwrap(),
        ) {
            Ok(inode) => {
                reply.entry(
                    &TTL,
                    &get_file_attr_from_filesystem_inode(inode, self.filesystem.superblock()),
                    0,
                );
            }
            Err(e) => reply.error(e as i32),
        }
    }
    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        match self
            .collection
            .iget(self.ino_to_nid(ino), self.filesystem.as_filesystem())
        {
            Ok(inode) => reply.attr(
                &TTL,
                &get_file_attr_from_filesystem_inode(inode, self.filesystem.superblock()),
            ),
            Err(e) => reply.error(e as i32),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        match self.try_read_link(ino) {
            Ok(symlink) => reply.data(&symlink),
            Err(e) => reply.error(e as i32),
        }
    }

    fn read(
        &mut self,
        _req: &Request,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock: Option<u64>,
        reply: ReplyData,
    ) {
        match self.try_read(ino, offset, size) {
            Ok(data) => reply.data(&data),
            Err(e) => reply.error(e as i32),
        }
    }
    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        match self
            .collection
            .iget(self.ino_to_nid(ino), self.filesystem.as_filesystem())
        {
            Ok(_) => reply.opened(0, 0),
            Err(e) => reply.error(e as i32),
        }
    }
    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        match self
            .collection
            .iget(self.ino_to_nid(ino), self.filesystem.as_filesystem())
        {
            Ok(_) => reply.opened(0, 0),
            Err(e) => reply.error(e as i32),
        }
    }
    fn releasedir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _flags: i32,
        reply: fuser::ReplyEmpty,
    ) {
        self.collection.release(self.ino_to_nid(ino));
        reply.ok()
    }
    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: fuser::ReplyEmpty,
    ) {
        self.collection.release(self.ino_to_nid(ino));
        reply.ok()
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct ErofsArgs {
    #[arg(short, long)]
    image: String,
    #[arg(short, long)]
    mountpoint: String,
}
fn main() {
    let args = ErofsArgs::parse();
    let file = File::options()
        .read(true)
        .write(true)
        .open(Path::new(&args.image))
        .unwrap();
    let filesystem =
        Box::new(ImageFileSystem::try_new(UncompressedBackend::new(FuseFile(file))).unwrap());
    let collection = FuseCollection(HashMap::new());
    let erofs_fuse = ErofsFuse {
        filesystem,
        collection,
    };
    fuser::mount2(
        erofs_fuse,
        args.mountpoint,
        &[
            MountOption::FSName("erofs_fuse_rs".to_string()),
            MountOption::AutoUnmount,
        ],
    )
    .unwrap()
}

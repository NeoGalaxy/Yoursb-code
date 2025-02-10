use alloc::vec;
use chacha20poly1305::aead::heapless;
use core::{iter, ops::RangeInclusive};

use alloc::{string::String, vec::Vec};
use rand::{distributions::Uniform, rngs::OsRng, Rng};

use crate::{
    crypto::{create_key, decrypt_key, Decrypter, Encrypter, YsbcRead, BUFFER_LEN, TAG_SIZE},
    interfaces::{
        indicate, CharsDist, Context, DecryptedFile, DecryptedPassword, ElementId, FileLeaf,
        FilePath, InitInstanceContext, Instance, NewPasswordDetails, Password, PathOrLeaf,
        WritableInstance,
    },
};

#[derive(Debug)]
pub struct Commands<Ctx>(pub Ctx);

#[derive(Debug)]
pub struct InstanceCommands<'ctx, Ctx: Context> {
    pub ctx: &'ctx Commands<Ctx>,
    pub instance: Ctx::Instance,
}

impl<Ctx: Context> Commands<Ctx> {
    pub fn new(ctx: Ctx) -> Self {
        Self(ctx)
    }

    pub fn get_instance(
        &self,
        loc: Option<Ctx::InstanceLoc>,
    ) -> Result<InstanceCommands<Ctx>, Ctx::Error> {
        let loc = if let Some(loc) = loc {
            loc
        } else {
            Ctx::Instance::locate()?
        };
        Ok(InstanceCommands {
            ctx: self,
            instance: Ctx::Instance::open(loc)?,
        })
    }
}

impl<Ctx: InitInstanceContext> InstanceCommands<'_, Ctx>
where
    Ctx::Instance: WritableInstance<Ctx>,
{
    /// Add a password to the instance
    pub fn new_password(
        &mut self,
        id: Ctx::FileLeaf<true>,
        data: Option<String>,
        password: NewPasswordDetails<Ctx>,
    ) -> Result<DecryptedPassword<Ctx>, Ctx::Error> {
        indicate!(&self.ctx.0, "New password will be saved as {:?}", id);

        let password = match password {
            NewPasswordDetails::Known(pass) => pass,
            NewPasswordDetails::Prompt => {
                todo!()
            }
            NewPasswordDetails::Random { len, allowed_chars } => {
                indicate!(
                    &self.ctx.0,
                    "Generating random password of length {:?}...",
                    len
                );
                let nb_chars_possible = allowed_chars
                    .char_ranges()
                    .fold(0, |acc, (start, end)| acc + 1 + end as u32 - start as u32);
                let mut content = String::with_capacity(len.into());
                let rand_indexes = OsRng
                    .sample_iter(Uniform::new_inclusive(0, nb_chars_possible - 1))
                    .take(len as usize);
                'indexes_loop: for mut char_idx in rand_indexes {
                    // TODO: check if the time this takes to generate gives an indication
                    // on the generated value
                    for current_range in allowed_chars.char_ranges() {
                        if char_idx > current_range.1 as u32 - current_range.0 as u32 {
                            char_idx -= 1 + current_range.1 as u32 - current_range.0 as u32;
                            continue;
                        }
                        // Found the char
                        let c = RangeInclusive::new(current_range.0, current_range.1)
                            .nth(char_idx as usize)
                            .unwrap();
                        content.push(c);
                        continue 'indexes_loop;
                    }
                    unreachable!("`i` should always be in range of the allowed_chars")
                }
                assert_eq!(content.len(), len as usize);
                content
            }
        };

        let value = Password { password, data };

        let encrypted_key = self.instance.get_key()?;
        let passphrase = self
            .ctx
            .0
            .prompt_secret("Please enter your instance passphrase");

        let key = decrypt_key(encrypted_key, passphrase).unwrap();

        let content = match serde_json::to_string(&value) {
            Ok(c) => c,
            Err(e) => todo!("serde error: {}", e),
        };

        let mut encrypter = Encrypter::new(content.as_bytes(), &key).unwrap();
        let encrypted_content: Vec<u8> = iter::repeat(())
            .map(|()| {
                let mut buf = heapless::Vec::<u8, { BUFFER_LEN + TAG_SIZE }>::new();
                buf.resize_default(BUFFER_LEN + TAG_SIZE).unwrap();
                let read_size = encrypter.read(&mut buf).unwrap();
                buf.truncate(read_size);
                buf
            })
            .take_while(|b| !b.is_empty())
            .flatten()
            .collect();

        self.instance
            .write_element(&id, encrypted_content.as_slice())?;

        indicate!(&self.ctx.0, "Password saved");

        Ok(DecryptedPassword {
            id: ElementId(id),
            value,
        })
    }

    pub fn encrypt_file<R>(
        &mut self,
        DecryptedFile { id, content }: DecryptedFile<Ctx, R>,
    ) -> Result<(), Ctx::Error>
    where
        R: YsbcRead,
    {
        let encrypted_key = self.instance.get_key()?;
        let passphrase = self
            .ctx
            .0
            .prompt_secret("Please enter your instance passphrase");

        let key = decrypt_key(encrypted_key, passphrase).unwrap();

        let encrypted_content = Encrypter::new(content, &key).ok().unwrap();

        self.instance.write_element(&id.0, encrypted_content)?;

        Ok(())
    }

    pub fn delete_element<const IS_PASSWORD: bool>(
        &mut self,
        id: &Ctx::FileLeaf<IS_PASSWORD>,
    ) -> Result<(), Ctx::Error> {
        self.instance.delete_element(id)
    }
}

impl<Ctx: Context> InstanceCommands<'_, Ctx> {
    pub fn list_content<'a, const IS_PASSWORD: bool>(
        &'a self,
        root_dir: Ctx::FilePath<IS_PASSWORD>,
        pattern: &'a str,
    ) -> impl Iterator<Item = Result<ElementId<Ctx, IS_PASSWORD>, Ctx::Error>> + 'a {
        struct Iter<'a, Ctx: Context, const IS_PASSWORD: bool> {
            instance: &'a <Ctx as Context>::Instance,
            root_dir: Ctx::FilePath<IS_PASSWORD>,
            pattern: &'a str,
            to_check: Vec<PathOrLeaf<Ctx, IS_PASSWORD>>,
            valid: Vec<PathOrLeaf<Ctx, IS_PASSWORD>>,
            errs: Vec<Ctx::Error>,
        }

        impl<Ctx: Context, const IS_PASSWORD: bool> Iterator for Iter<'_, Ctx, IS_PASSWORD> {
            type Item = Result<ElementId<Ctx, IS_PASSWORD>, Ctx::Error>;

            fn next(&mut self) -> Option<Self::Item> {
                // Return the remaining errors
                match self.errs.pop() {
                    None => (),
                    Some(e) => return Some(Err(e)),
                }

                // Check the remaining valid paths
                match self.valid.pop() {
                    None => (),
                    Some(PathOrLeaf::Path(dir)) => {
                        // If it errors out, the element is pop'ed and
                        // the error is returned, so everything is fine
                        let content = match self.instance.list_content(dir) {
                            Ok(c) => c,
                            Err(e) => return Some(Err(e)),
                        };
                        for elmt in content {
                            match elmt {
                                Ok(e) => self.valid.push(e),
                                Err(err) => {
                                    self.errs.push(err);
                                }
                            };
                        }

                        // now we populated valid, get the next element
                        return self.next();
                    }
                    Some(PathOrLeaf::Leaf(file)) => {
                        return Some(Ok(ElementId(file)));
                    }
                }

                // Check the other unexplored paths
                match self.to_check.pop() {
                    None => (),
                    Some(PathOrLeaf::Path(path)) => {
                        let suffix = path.get_suffix(&self.root_dir);
                        if suffix.starts_with(self.pattern) {
                            // it actually is vaid
                            self.valid.push(PathOrLeaf::Path(path));
                            // skip the current element
                            return self.next();
                        }
                        if !self.pattern.starts_with(suffix) {
                            // The suffix doesn't follow the beginning of the pattern
                            // => skip
                            return self.next();
                        }

                        let content = match self.instance.list_content(path) {
                            Ok(c) => c,
                            Err(e) => return Some(Err(e)),
                        };
                        for elmt in content {
                            match elmt {
                                Ok(e) => self.to_check.push(e),
                                Err(err) => {
                                    self.errs.push(err);
                                }
                            };
                        }

                        // now we populated self.valid, get the next element
                        return self.next();
                    }
                    Some(PathOrLeaf::Leaf(file)) => {
                        let suffix = file.get_suffix(&self.root_dir);
                        if suffix.starts_with(self.pattern) {
                            return Some(Ok(ElementId(file)));
                        } else {
                            // skip
                            return self.next();
                        }
                    }
                }

                // Everything is empty => nothing to explore
                None
            }
        }

        Iter {
            instance: &self.instance,
            to_check: vec![PathOrLeaf::<Ctx, IS_PASSWORD>::Path(root_dir.clone())],
            root_dir,
            pattern,
            valid: vec![],
            errs: vec![],
        }
    }

    pub fn get_password(
        &mut self,
        id: Ctx::FileLeaf<true>,
    ) -> Result<DecryptedPassword<Ctx>, Ctx::Error> {
        let encrypted_key = self.instance.get_key()?;
        let passphrase = self
            .ctx
            .0
            .prompt_secret("Please enter your instance passphrase");

        let key = decrypt_key(encrypted_key, passphrase).unwrap();

        let encrypted_content = self.instance.get_element(&id)?;

        let mut decrypter = Decrypter::new(encrypted_content, &key).ok().unwrap();
        let content: Vec<u8> = iter::repeat(())
            .map(|()| {
                let mut buf = heapless::Vec::<u8, { BUFFER_LEN + TAG_SIZE }>::new();
                buf.resize_default(BUFFER_LEN + TAG_SIZE).unwrap();
                let read_size = decrypter.read(&mut buf).ok().unwrap();
                buf.truncate(read_size);
                buf
            })
            .take_while(|b| !b.is_empty())
            .flatten()
            .collect();

        let value = match serde_json::from_slice(&content) {
            Ok(c) => c,
            Err(e) => panic!(
                "serde error: {}\ncontent: \n{}\n-----",
                e,
                String::from_utf8_lossy(&content)
            ),
        };

        indicate!(&self.ctx.0, "Password decrypted.");

        Ok(DecryptedPassword {
            id: ElementId(id),
            value,
        })
    }

    pub fn decrypt_file(
        &mut self,
        id: Ctx::FileLeaf<false>,
    ) -> Result<DecryptedFile<Ctx, Decrypter<Ctx::FileRead>>, Ctx::Error> {
        let encrypted_key = self.instance.get_key()?;
        let passphrase = self
            .ctx
            .0
            .prompt_secret("Please enter your instance passphrase");

        let key = decrypt_key(encrypted_key, passphrase).unwrap();

        let encrypted_content = self.instance.get_element(&id)?;

        let decrypter = Decrypter::new(encrypted_content, &key).ok().unwrap();

        Ok(DecryptedFile {
            id: ElementId(id),
            content: decrypter,
        })
    }
}

impl<Ctx: InitInstanceContext> Commands<Ctx>
where
    Ctx::Instance: WritableInstance<Ctx>,
{
    pub fn init_intance(
        &self,
        path: Ctx::InstanceLoc,
        passphrase: Option<&str>,
    ) -> Result<InstanceCommands<Ctx>, Ctx::Error> {
        indicate!(&self.0, "Creating a new YourSBCode instance at {path}.");
        let mut binding = None;
        let passphrase = passphrase.unwrap_or_else(|| {
            binding = Some(
                self.0
                    .prompt_secret("Please create a master passphrase for the instance:"),
            );
            binding.as_ref().unwrap().as_ref()
        });
        let key = create_key(passphrase, &self.0);
        Ok(InstanceCommands {
            ctx: self,
            instance: Ctx::new_instance(path, key)?,
        })
    }
}

impl<Ctx: InitInstanceContext> InstanceCommands<'_, Ctx>
where
    Ctx::Instance: WritableInstance<Ctx>,
{
    pub fn del_intance(self) -> Result<(), (Ctx::Error, Self)> {
        self.instance.delete().map_err(|(err, i)| {
            (
                err,
                Self {
                    ctx: self.ctx,
                    instance: i,
                },
            )
        })
        // TODO: put Instance.delete in init ?
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::testing::{PathBufLeaf, TestCDist, TestCtx};

    use super::*;
    use core::str;
    use std::{
        path::{Path, PathBuf},
        prelude::rust_2021::*,
        println,
    };

    #[test]
    fn test_create_read_password() {
        let ctx = Commands::new(TestCtx);
        let mut commands = ctx
            .get_instance(Some("tests/instances/basic".to_string()))
            .unwrap();

        let new_pass = commands
            .new_password(
                PathBufLeaf(PathBuf::from("hello")),
                Some("random pass".to_string()),
                NewPasswordDetails::Random {
                    len: 20,
                    allowed_chars: TestCDist,
                },
            )
            .unwrap();
        println!("{new_pass:?}");

        let found_pass = commands
            .get_password(PathBufLeaf(PathBuf::from("hello")))
            .unwrap();
        println!("{found_pass:?}");
        assert_eq!(
            serde_json::to_string(&new_pass.value).ok(),
            serde_json::to_string(&found_pass.value).ok()
        );
    }

    #[test]
    fn test_create_read_file() {
        let ctx = Commands::new(TestCtx);
        let mut commands = ctx
            .get_instance(Some("tests/instances/basic".to_string()))
            .unwrap();

        let new_file_content = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
                sed do eiusmod tempor incididunt ut labore et dolore magna \
                aliqua. Ut enim ad minim veniam, quis nostrud exercitation \
                ullamco laboris nisi ut aliquip ex ea commodo consequat."
            .as_slice();
        let new_file = DecryptedFile {
            id: ElementId(PathBufLeaf(PathBuf::from("hello_world"))),
            content: new_file_content,
        };
        commands.encrypt_file(new_file).unwrap();
        println!("{:?}", str::from_utf8(new_file_content).unwrap());

        let mut found_file = commands
            .decrypt_file(PathBufLeaf(PathBuf::from("hello_world")))
            .unwrap();
        let content: Vec<u8> = iter::repeat(())
            .map(|()| {
                let mut buf = heapless::Vec::<u8, { BUFFER_LEN + TAG_SIZE }>::new();
                buf.resize_default(BUFFER_LEN + TAG_SIZE).unwrap();
                let read_size = found_file.content.read(&mut buf).unwrap();
                buf.truncate(read_size);
                buf
            })
            .take_while(|b| !b.is_empty())
            .flatten()
            .collect();
        println!("{:?}", str::from_utf8(&content).unwrap());
        assert_eq!(&new_file_content, &content);
    }

    #[test]
    fn test_create_delete_instance() {
        let ctx = Commands::new(TestCtx);
        let mut commands = ctx
            .init_intance(
                "tests/instances/tmp".to_string(),
                Some(TestCtx::INSTANCE_PASS),
            )
            .unwrap();

        let content = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
                sed do eiusmod tempor incididunt ut labore et dolore magna \
                aliqua. Ut enim ad minim veniam, quis nostrud exercitation \
                ullamco laboris nisi ut aliquip ex ea commodo consequat."
            .as_slice();
        let new_file = DecryptedFile {
            id: ElementId(PathBufLeaf(PathBuf::from("hello_world"))),
            content,
        };
        commands.encrypt_file(new_file).unwrap();
        println!("{:?}", str::from_utf8(content).unwrap());

        assert!(Path::new("tests/instances/tmp/files/hello_world").is_file());

        commands.del_intance().unwrap();
        assert!(!Path::new("tests/instances/tmp").exists());
    }
}

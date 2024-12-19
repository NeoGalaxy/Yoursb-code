use alloc::vec;
use core::ops::RangeInclusive;

use alloc::{string::String, vec::Vec};
use rand::{distributions::Uniform, rngs::OsRng, Rng};

use crate::interfaces::{
    indicate, CharsDist, Context, DecryptedFile, DecryptedPassword, FileId, FileLeaf, FilePath,
    InitInstanceContext, Instance, NewPasswordDetails, Password, PasswordId, PathOrLeaf,
};

// pub struct Commands<Ctx>(PhantomData<Ctx>);
pub struct Commands<Ctx>(pub Ctx);
pub struct InstanceCommands<'ctx, Ctx: Context> {
    ctx: &'ctx Commands<Ctx>,
    instance: Ctx::Instance,
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
            Ctx::Instance::locate()
        };
        Ok(InstanceCommands {
            ctx: self,
            instance: Ctx::Instance::open(loc)?,
        })
    }
    //locate
}

impl<'ctx, Ctx: Context> InstanceCommands<'ctx, Ctx> {
    pub fn new_password(
        &mut self,
        id: Ctx::FileLeaf<true>,
        data: Option<String>,
        password: NewPasswordDetails<Ctx>,
    ) -> Result<DecryptedPassword<Ctx>, Ctx::Error> {
        indicate!(&self.ctx.0, "New password will be saved as {:?}", id);

        let password = match password {
            NewPasswordDetails::Known(pass) => pass,
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
                    unreachable!("i should always be in range of the allowed_chars")
                }
                assert_eq!(content.len(), len as usize);
                content
            }
        };

        let password = Password { password, data };

        let key = self.instance.unlock_key(self.ctx)?;

        indicate!(&self.ctx.0, "New password will be saved as {:?}", id);

        let content = match serde_json::to_string(&password) {
            Ok(c) => c,
            Err(e) => todo!("error: {}", e),
        };

        self.instance.write_element(&id, content.clone())?;

        Ok(DecryptedPassword {
            id: PasswordId(id),
            value: password,
        })
    }

    pub fn list_passwords<'a>(
        &'a self,
        root_dir: Ctx::FilePath<true>,
        pattern: &'a str,
    ) -> impl Iterator<Item = Result<PasswordId<Ctx>, Ctx::Error>> + 'a {
        struct Iter<'a, Ctx: Context> {
            instance: &'a <Ctx as Context>::Instance,
            root_dir: Ctx::FilePath<true>,
            pattern: &'a str,
            to_check: Vec<PathOrLeaf<Ctx, true>>,
            valid: Vec<PathOrLeaf<Ctx, true>>,
            errs: Vec<Ctx::Error>,
        }

        impl<Ctx: Context> Iterator for Iter<'_, Ctx> {
            type Item = Result<PasswordId<Ctx>, Ctx::Error>;

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
                        return Some(Ok(PasswordId(file)));
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
                            return Some(Ok(PasswordId(file)));
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
            to_check: vec![PathOrLeaf::Path(root_dir.clone())],
            root_dir,
            pattern,
            valid: vec![],
            errs: vec![],
        }
    }

    // pub fn encrypt<const IS_PASSWORD: bool>(
    //     id: Ctx::FilePath<IS_PASSWORD>,
    //     content: ,
    // ) -> FileId<Ctx> {
    //     todo!()
    // }

    pub fn list_files(prefix: Ctx::FilePath<false>) -> impl Iterator<Item = FileId<Ctx>> {
        todo!();
        [].into_iter()
    }
}

impl<Ctx: Context> FileId<Ctx> {
    pub fn read(self, instance: Ctx::Instance) -> Result<DecryptedFile<Ctx>, Self> {
        todo!()
    }
}

impl<Ctx: Context> PasswordId<Ctx> {
    pub fn read(self, instance: Ctx::Instance) -> Result<DecryptedPassword<Ctx>, Self> {
        todo!()
    }
}

impl<Ctx: InitInstanceContext> Commands<Ctx> {
    pub fn init_intance(&self, path: Ctx::InstanceLoc) -> InstanceCommands<Ctx> {
        InstanceCommands {
            ctx: self,
            instance: Ctx::new_instance(path),
        }
    }
}

impl<Ctx: InitInstanceContext> InstanceCommands<'_, Ctx> {
    pub fn del_intance(self, _force: bool) -> Result<(), Ctx::Error> {
        self.instance.delete()
        // TODO: put Instance.delete in init ?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_passwords() {}
}

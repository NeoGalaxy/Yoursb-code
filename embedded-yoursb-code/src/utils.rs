macro_rules! eprintln {
	($format:literal, $($e:expr),* $(,)?) => {
        libc::fprintf(
        	libc::fdopen(libc::STDERR_FILENO, "w".as_ptr() as _),
        	concat!($format, "\n\0").as_ptr() as _, $($e),*
        )
	};
	($format:literal) => {
		eprintln!($format,)
	};

	() => {
		eprintln!("",)
	};
}

pub(crate) use eprintln;

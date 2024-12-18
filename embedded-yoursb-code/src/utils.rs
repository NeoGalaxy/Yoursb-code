macro_rules! printfln {
	($format:literal, $($e:expr),* $(,)?) => {
        libc::printf(
        	concat!($format, "\n\0").as_ptr() as _,
        	$($e),*
        )
	};
	($format:literal) => {
		printfln!($format,)
	};

	() => {
		printfln!("",)
	};
}

pub(crate) use printfln;

macro_rules! eprintfln {
	($format:literal, $($e:expr),* $(,)?) => {
        libc::fprintf(
        	libc::fdopen(libc::STDERR_FILENO, "w".as_ptr() as _),
        	concat!($format, "\n\0").as_ptr() as _,
        	$($e),*
        )
	};
	($format:literal) => {
		eprintfln!($format,)
	};

	() => {
		eprintfln!("",)
	};
}

pub(crate) use eprintfln;

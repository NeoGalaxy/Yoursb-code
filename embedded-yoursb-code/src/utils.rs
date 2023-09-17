macro_rules! println {
	($format:literal, $($e:expr),* $(,)?) => {
	    libc::printf(concat!($format, "\n\0").as_ptr() as _, $($e),*)
	};
	($format:literal) => {
		println!($format,)
	};

	() => {
		println!("",)
	};
}

pub(crate) use println;

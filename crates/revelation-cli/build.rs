fn main() {
    #[cfg(windows)]
    {
        let mut res = winres::WindowsResource::new();
        res.set_icon("revelation.ico"); 
        res.compile().unwrap();
    }
}

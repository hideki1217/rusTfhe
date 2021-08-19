
pub fn transmute<I:Sized,O:Sized>(mut item:I)->O {
    assert!(core::mem::size_of::<I>() == core::mem::size_of::<O>());
    let ptr = &mut item as *mut _ as *mut O;
    let res = unsafe{ ptr.read() };
    core::mem::forget(item);
    res
}
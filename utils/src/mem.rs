use std::mem::MaybeUninit;

pub fn transmute<I: Sized, O: Sized>(mut item: I) -> O {
    assert!(core::mem::size_of::<I>() == core::mem::size_of::<O>());
    let ptr = &mut item as *mut _ as *mut O;
    let res = unsafe { ptr.read() };
    core::mem::forget(item);
    res
}

#[inline]
/// # Caution
/// ## item_iter's length must be more than N
pub unsafe fn array_create<T, I, const N: usize>(item_iter: I) -> [T; N]
where
    I: std::iter::Iterator<Item = T>,
{
    let mut arr: [MaybeUninit<T>; N] = MaybeUninit::uninit().assume_init();
    arr.iter_mut()
        .zip(item_iter)
        .for_each(|(arr_i, item)| *arr_i = MaybeUninit::new(item));
    transmute::<_, [T; N]>(arr)
}

#[inline]
/// # Caution
/// ## item_iter's length must be more than N
pub fn array_create_enumerate<T, F, const N: usize>(init: F) -> [T; N]
where
    F: FnMut(usize) -> T,
{
    let mut arr: [MaybeUninit<T>; N] = unsafe { MaybeUninit::uninit().assume_init() };
    arr.iter_mut()
        .zip((0..N).map(init))
        .for_each(|(arr_i, item)| *arr_i = MaybeUninit::new(item));
    transmute::<_, [T; N]>(arr)
}

// Lebar/tinggi bar dan flexGrow bergantung pada data, jadi tidak bisa dipindah ke kelas CSS
// statis. Policy CSP kita memakai `style-src 'self'` tanpa 'unsafe-inline', dan atribut
// `style` di markup (termasuk yang ditulis React lewat style={{ … }}) ditolak peramban sebagai
// inline style. Penulisan lewat CSSOM tidak dibatasi style-src — dibuktikan secara lokal dengan
// pembanding: atribut style tidak diterapkan, properti CSSOM diterapkan tanpa pelanggaran.
//
// Ref callback dipakai (bukan useEffect) agar gaya terpasang pada commit yang sama, sebelum
// paint, sehingga tidak pernah terlihat kedip lebar 0.
type SizeProperty = 'width' | 'height' | 'flexGrow'

export function styleValue<T extends HTMLElement>(property: SizeProperty, value: string | number) {
  return (element: T | null) => {
    if (element) element.style[property] = String(value)
  }
}

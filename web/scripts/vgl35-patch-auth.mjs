// @ts-check
/// <reference types="node" />
// VGL-35 — Tahap 1: halaman autentikasi dari kolom sempit terpusat menjadi dua kolom.
import { readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'

/**
 * @param {string} rel
 * @param {Array<[string, string]>} edits
 */
function patch(rel, edits) {
  const file = resolve(process.cwd(), rel)
  const raw = readFileSync(file, 'utf8')
  const crlf = raw.includes('\r\n')
  let s = crlf ? raw.replace(/\r\n/g, '\n') : raw
  for (const [from, to] of edits) {
    if (!s.includes(from)) throw new Error(`${rel}: tidak ditemukan ->\n${from}`)
    if (s.split(from).length !== 2) throw new Error(`${rel}: tidak unik ->\n${from}`)
    s = s.replace(from, to)
  }
  writeFileSync(file, crlf ? s.replace(/\n/g, '\r\n') : s, 'utf8')
  console.log(`patched ${rel} (CRLF=${crlf})`)
}

const GRID =
  '      <div className="grid gap-10 pt-12 sm:pt-16 lg:grid-cols-[minmax(0,1fr)_minmax(0,460px)] lg:gap-16 lg:pt-20">\n'

patch('src/pages/LoginPage.tsx', [
  [
    '    <Container className="pb-16">\n      <div className="mx-auto max-w-[480px] pt-16">\n',
    `    <Container className="pb-16 sm:pb-20">\n${GRID}        <div className="max-w-[560px]">\n`,
  ],
  [
    `        <p className="type-small mt-3 text-ink-soft">
          Akun diperlukan untuk menyimpan riwayat secara permanen dan membuka dashboard.
          Pemeriksaan dasar tetap bisa dilakukan tanpa akun.
        </p>
`,
    `        <p className="type-small mt-3 text-ink-soft">
          Akun diperlukan untuk menyimpan riwayat secara permanen dan membuka dashboard.
          Pemeriksaan dasar tetap bisa dilakukan tanpa akun.
        </p>

        <ul className="mt-8 flex flex-col gap-3 border-t border-line pt-6 text-sm">
          {[
            'Periksa tautan atau pesan tanpa akun lebih dulu.',
            'Riwayat tersimpan permanen begitu akun aktif.',
            'Dashboard terbuka setelah email diverifikasi.',
          ].map((item) => (
            <li key={item} className="flex items-start gap-2.5 text-ink-soft">
              <Check size={16} className="mt-0.5 shrink-0 text-accent" aria-hidden="true" />
              {item}
            </li>
          ))}
        </ul>

        <Link
          to="/periksa"
          className={buttonStyles({ variant: 'ghost', size: 'sm', className: 'mt-6 -ml-2' })}
        >
          Periksa tanpa akun
          <ArrowRight size={15} aria-hidden="true" />
        </Link>
        </div>

        <div className="min-w-0">
`,
  ],
  [
    `            <p className="type-caption mt-4">
              Sesi akun dipulihkan secara otomatis oleh layanan akun. Data riwayat hanya dimuat
              untuk pengguna yang sedang masuk.
            </p>
          </>
        ) : null}
      </div>
`,
    `            <p className="type-caption mt-4">
              Sesi akun dipulihkan secara otomatis oleh layanan akun. Data riwayat hanya dimuat
              untuk pengguna yang sedang masuk.
            </p>
          </>
        ) : null}
        </div>
      </div>
`,
  ],
])

patch('src/pages/RegisterPage.tsx', [
  [
    "import { ArrowRight, UserPlus } from 'lucide-react'",
    "import { ArrowRight, Check, UserPlus } from 'lucide-react'",
  ],
  [
    '    <Container className="pb-16">\n      <div className="mx-auto max-w-[440px] pt-16">\n',
    `    <Container className="pb-16 sm:pb-20">\n${GRID}        <div className="max-w-[560px]">\n`,
  ],
  [
    `        <p className="type-small mt-3 text-ink-soft">
          Dengan akun, hasil pemeriksaan tersimpan di riwayat dan dashboard dapat menampilkan
          ringkasan aktivitasmu.
        </p>
`,
    `        <p className="type-small mt-3 text-ink-soft">
          Dengan akun, hasil pemeriksaan tersimpan di riwayat dan dashboard dapat menampilkan
          ringkasan aktivitasmu.
        </p>

        <ul className="mt-8 flex flex-col gap-3 border-t border-line pt-6 text-sm">
          {[
            'Satu username hanya dipakai satu akun di seluruh aplikasi.',
            'Email dikonfirmasi lewat tautan verifikasi sebelum fitur akun terbuka.',
            'Kata sandi dikelola layanan akun, tidak disimpan di data pemeriksaan.',
          ].map((item) => (
            <li key={item} className="flex items-start gap-2.5 text-ink-soft">
              <Check size={16} className="mt-0.5 shrink-0 text-accent" aria-hidden="true" />
              {item}
            </li>
          ))}
        </ul>
        </div>

        <div className="min-w-0">
`,
  ],
  [
    `            <Alert tone="info" className="mt-4">
              Layanan akun mengelola data masuk akun. VERIGUARD AI tidak menyimpan kata sandi di
              data pemeriksaan atau di browser ini.
            </Alert>
          </>
        ) : null}
      </div>
`,
    `            <Alert tone="info" className="mt-4">
              Layanan akun mengelola data masuk akun. VERIGUARD AI tidak menyimpan kata sandi di
              data pemeriksaan atau di browser ini.
            </Alert>
          </>
        ) : null}
        </div>
      </div>
`,
  ],
])

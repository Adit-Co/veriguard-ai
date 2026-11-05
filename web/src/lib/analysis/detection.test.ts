import { describe, expect, it } from 'vitest'
import { analyzeLink, analyzeMessage } from './index'
import {
  detectBrand,
  findBrandDomainPrefix,
  getRegistrableDomain,
  hostsFromLink,
} from './link'
import { createScan, isScanResult } from '../storage/scanStore'
import { foldConfusables, isLookalike } from './text'
import { AnalysisError } from './validate'

// Tes ini adalah regresi berbasis kasus terverifikasi, bukan klaim akurasi.
// Tidak ada korpus berlabel Indonesia yang tersedia, jadi angka presisi/recall
// keseluruhan tidak dapat dinyatakan dari berkas ini.

describe('pencocokan kemiripan nama merek', () => {
  it('melipat karakter pengganti pada kedua sisi', () => {
    expect(foldConfusables('paypa1')).toBe('paypal')
    expect(foldConfusables('m1crosoft')).toBe('mlcrosoft')
    expect(foldConfusables('rnandiri')).toBe('mandiri')
  })

  it('mengenali varian satu langkah tulis', () => {
    expect(isLookalike('paypai', 'paypal')).toBe(true)
    expect(isLookalike('paypat', 'paypal')).toBe(true)
    expect(isLookalike('lazado', 'lazada')).toBe(true)
    expect(isLookalike('mlcrosoft', 'microsoft')).toBe(true)
    expect(isLookalike('paypal', 'paypal')).toBe(false)
  })

  it('tidak menilai kata lain sebagai merek pendek', () => {
    expect(isLookalike('crab', 'grab')).toBe(false)
    expect(isLookalike('danu', 'dana')).toBe(false)
    expect(isLookalike('bcb', 'bca')).toBe(false)
    expect(isLookalike('myapple', 'apple')).toBe(false)
  })

  it('memakai kemiripan hanya bila merek tidak cocok sebagai token', () => {
    expect(detectBrand('paypaI.com')?.kind).toBe('typosquat')
    expect(detectBrand('paypat.com')?.kind).toBe('typosquat')
    expect(detectBrand('rnandiri.com')?.kind).toBe('typosquat')
    expect(detectBrand('m1crosoft.com')?.kind).toBe('typosquat')
    expect(detectBrand('bca-verifikasi-akun.example')?.kind).toBe('impersonation')
    expect(detectBrand('www.bca.co.id')?.kind).toBe('official')
  })
})

describe('normalisasi domain', () => {
  it('memakai kelas domain tingkat kedua .id yang lengkap', () => {
    expect(getRegistrableDomain('www.pajak.go.id')).toBe('pajak.go.id')
    expect(getRegistrableDomain('mail.universitas.ac.id')).toBe('universitas.ac.id')
    expect(getRegistrableDomain('www.bca.co.id')).toBe('bca.co.id')
    expect(getRegistrableDomain('tokopedia.com')).toBe('tokopedia.com')
  })
})

describe('regresi false positive merek', () => {
  it('tetap menilai tinggi pesan yang menyamar dengan permintaan OTP', () => {
    const result = analyzeMessage(
      'Akun BCA Anda diblokir. Kirim kode OTP Anda sekarang juga ke www.bca-verif.com untuk memulihkan saldo.',
    )

    expect(result.riskLevel).toBe('high')
    expect(result.reasons.some((reason) => reason.id === 'brand_link')).toBe(true)
    expect(
      result.patterns.some(
        (pattern) => pattern.id === 'otp_theft' && pattern.confidence === 'high',
      ),
    ).toBe(true)
  })

  it('tidak menaikkan risiko hanya karena nama merek muncul sebagai kata', () => {
    for (const url of [
      'https://pos-kopi-nusantara.com/menu',
      'https://bsi-cetak-baju.co.id/order',
      'https://hotel-jne-bandung.com',
    ]) {
      const result = analyzeLink(url)
      expect(result.riskLevel).toBe('low')
      expect(result.reasons.some((reason) => reason.id === 'brand_name_unconfirmed')).toBe(true)
      expect(result.reasons.some((reason) => reason.id === 'brand_impersonation')).toBe(false)
      expect(
        result.patterns.some(
          (pattern) => pattern.id === 'impersonation' && pattern.confidence === 'high',
        ),
      ).toBe(false)
    }
  })

  it('tetap menandai merek yang dipakai bersama permintaan akun', () => {
    const result = analyzeLink('https://bca-verifikasi-akun.example/login')

    expect(result.riskLevel).toBe('high')
    expect(result.reasons.some((reason) => reason.id === 'brand_impersonation')).toBe(true)
  })

  it('tidak menganggap subdomain berjenjang palsu pada domain resmi', () => {
    const result = analyzeLink('https://www.pajak.go.id/berita')

    expect(result.riskLevel).toBe('low')
    expect(result.reasons.some((reason) => reason.id === 'deep_subdomain')).toBe(false)
  })

  it('menandai merek dalam pesan tanpa permintaan data sebagai bukti belum lengkap', () => {
    const result = analyzeMessage(
      'Halo kak, promo produk BCA hari ini di tokonya ya, cek detailnya di bca-promo-harian.com',
    )

    expect(result.riskLevel).toBe('medium')
    expect(result.reasons.some((reason) => reason.id === 'brand_link')).toBe(false)
    expect(result.reasons.some((reason) => reason.id === 'brand_link_unconfirmed')).toBe(true)
    expect(
      result.patterns.some(
        (pattern) => pattern.id === 'impersonation' && pattern.confidence === 'high',
      ),
    ).toBe(false)
    expect(
      result.patterns.some(
        (pattern) => pattern.id === 'phishing' && pattern.confidence === 'high',
      ),
    ).toBe(false)
  })
})

describe('regresi false negative varian merek', () => {
  it('mengenali varian huruf yang sebelumnya lolos', () => {
    const bare = analyzeLink('https://paypat.com')
    expect(bare.riskLevel).toBe('medium')
    expect(bare.reasons.some((reason) => reason.id === 'brand_name_unconfirmed')).toBe(true)

    const withLogin = analyzeLink('https://paypaI.com/login')
    expect(withLogin.riskLevel).toBe('high')
    expect(withLogin.reasons.some((reason) => reason.id === 'brand_typosquat')).toBe(true)
  })
})

describe('regresi konteks pesan', () => {
  it('tidak memakai tekanan waktu untuk kata waktu biasa', () => {
    const result = analyzeMessage('Tolong kirim resi paketnya dong, biar aku cek posisinya sekarang.')

    expect(result.riskLevel).toBe('low')
    expect(result.reasons.some((reason) => reason.id === 'urgency_language')).toBe(false)
    expect(result.reasons.some((reason) => reason.id === 'time_reference')).toBe(true)
  })

  it('membedakan pembayaran yang sudah terjadi dari permintaan membayar', () => {
    const result = analyzeMessage(
      'Bu, invoice listrik bulan ini sudah dibayar kok, jadi tidak perlu transfer lagi ya.',
    )

    expect(result.riskLevel).toBe('low')
    expect(
      result.reasons.find((reason) => reason.id === 'money_request')?.severity,
    ).toBe('info')
  })

  it('tetap menangkap dorongan cepat yang eksplisit', () => {
    const result = analyzeMessage(
      'Verifikasi akun Anda sekarang juga sebelum layanan dibekukan, data pribadi diperlukan.',
    )

    expect(result.reasons.some((reason) => reason.id === 'urgency_language')).toBe(true)
    expect(result.patterns.some((pattern) => pattern.id === 'urgency')).toBe(true)
  })
})

describe('skor hanya dari alasan yang ditampilkan', () => {
  it('jumlah bobot alasan yang tampil konsisten dengan skor', () => {
    const result = analyzeMessage(
      'URGENT: akun BCA Anda diblokir segera verifikasi data pribadi Anda sekarang juga klik link ini www.bca-verif.com dan kirim OTP PIN password nik ktp biaya transfer hadiah menang',
    )
    const shownTotal = result.reasons.reduce((sum, reason) => sum + reason.weight, 0)

    expect(result.reasons.length).toBeLessThanOrEqual(8)
    expect(result.meta.signalCount).toBeGreaterThan(result.reasons.length)
    expect(result.riskScore).toBe(Math.min(100, shownTotal))
  })
})

function reasonIds(result: { reasons: { id: string }[] }): string[] {
  return result.reasons.map((reason) => reason.id)
}

describe('alamat tujuan di dalam tautan', () => {
  it('mengenali host tujuan pada parameter dan menilai identitasnya', () => {
    const result = analyzeLink('https://example.com/verify?url=https://bca-verifikasi.com/akun')
    const brand = result.reasons.find((reason) => reason.id === 'redirect_target_brand')

    expect(reasonIds(result)).toContain('external_target_url')
    expect(brand?.severity).toBe('danger')
    expect(result.riskScore).toBeGreaterThanOrEqual(40)
    expect(result.patterns.some((pattern) => pattern.id === 'impersonation')).toBe(true)
  })

  it('membaca alamat tujuan yang di-percent-encode', () => {
    const result = analyzeLink(
      'https://cdn.example.net/redirect?next=http%3A%2F%2Fbca-verif.com%2Flogin',
    )

    expect(reasonIds(result)).toContain('redirect_target_brand')
  })

  it('membaca alamat tujuan tanpa scheme di dalam jalur', () => {
    const result = analyzeLink('https://situs-casino.online/bca-verifikasi.com/akun')

    expect(reasonIds(result)).toContain('redirect_target_brand')
  })

  it('menandai alamat tujuan berupa IP', () => {
    const result = analyzeLink(
      'https://situs-casino.online/redirect?url=http://146.19.74.23/bca/login',
    )

    expect(reasonIds(result)).toContain('redirect_target_ip')
  })

  it('tidak menganggap tujuan sesama domain sebagai alamat tersembunyi', () => {
    const result = analyzeLink(
      'https://sso.kampus.ac.id/login?service=https://perpustakaan.kampus.ac.id/buku',
    )

    expect(reasonIds(result)).not.toContain('external_target_url')
    expect(result.riskLevel).toBe('low')
  })

  it('mengembalikan host tujuan lewat hostsFromLink', () => {
    expect(hostsFromLink('https://example.com/go?to=bca-verifikasi.com/akun')).toEqual([
      'example.com',
      'bca-verifikasi.com',
    ])
    expect(hostsFromLink('bukan-alamat')).toEqual([])
  })
})

describe('domain resmi sebagai awalan', () => {
  it('menemukan domain merek yang hanya menjadi awalan host', () => {
    expect(findBrandDomainPrefix('www.bca.co.id.verify-secure.top')?.name).toBe('bca')
    expect(findBrandDomainPrefix('www.bca.co.id')).toBeNull()
  })

  it('satu fakta merek tidak dihitung dua kali', () => {
    const result = analyzeLink('https://www.bca.co.id.verify-secure.top/akun')
    const ids = reasonIds(result)

    expect(ids).toContain('brand_domain_prefix')
    expect(ids).not.toContain('brand_impersonation')
    expect(ids).toContain('brand_credential_combo')
    expect(result.riskLevel).toBe('high')
  })
})

describe('merek pada label yang tidak utuh', () => {
  it('mengenali merek dengan imbuhan angka', () => {
    expect(detectBrand('88bca-verifikasi.best')?.kind).toBe('impersonation')
    expect(detectBrand('88bca-verifikasi.best')?.glued).toBeUndefined()
  })

  it('mengenali merek yang menempel tanpa pemisah, bukan kata biasa', () => {
    expect(detectBrand('xxsicepatxx.com')?.glued).toBe(true)
    expect(detectBrand('pineapplecafe.com')).toBeNull()

    const result = analyzeLink('https://xxsicepatxx.com')
    expect(reasonIds(result)).toContain('brand_name_glued')
    expect(result.riskLevel).toBe('low')
  })
})

describe('nama merek di luar domain', () => {
  it('membedakan segmen merek dengan kata yang hanya mengandung merek', () => {
    expect(reasonIds(analyzeLink('https://1a2b3c4d5e6f7g8.xyz/paypal'))).toContain(
      'brand_path_only',
    )
    expect(reasonIds(analyzeLink('https://perpusda.go.id/katalog/buku-permata-biru'))).not.toContain(
      'brand_path_only',
    )
  })

  it('menambah bukti gabungan merek dan kata hadiah tanpa naik ke tinggi', () => {
    const result = analyzeLink('https://shopee-piuhadi.com/promo')

    expect(reasonIds(result)).toContain('brand_giveaway_combo')
    expect(result.riskLevel).toBe('medium')
  })
})

describe('bentuk URL yang menyulitkan pembacaan alamat', () => {
  it('menandai garis miring ganda dan domain berimbuhan protokol', () => {
    expect(reasonIds(analyzeLink('https://example.com//go?to=contoh.com'))).toContain(
      'double_slash_path',
    )
    expect(reasonIds(analyzeLink('https://https-palingsaleh.co/verifikasi-akun'))).toContain(
      'scheme_like_host',
    )
    expect(reasonIds(analyzeLink('https://httpbin.org/get'))).not.toContain('scheme_like_host')
  })
})

describe('keyakinan pola ditentukan konteks, bukan keberadaan kata', () => {
  function confidenceOf(
    result: { patterns: { id: string; confidence: string }[] },
    id: string,
  ): string | undefined {
    return result.patterns.find((pattern) => pattern.id === id)?.confidence
  }

  it('kata akun di domain resmi tidak dianggap halaman login palsu', () => {
    const official = analyzeLink(
      'https://m.tokopedia.com/notifikasi?redirect=https%3A%2F%2Fwww.tokopedia.com%2Faccount',
    )

    expect(reasonIds(official)).toContain('credential_keywords')
    expect(confidenceOf(official, 'fake_login')).toBe('low')
  })

  it('kata akun pada domain tiruan naik menjadi bukti kuat', () => {
    const lookalike = analyzeLink('https://bca-verifikasi-akun.top/login')

    expect(confidenceOf(lookalike, 'fake_login')).toBe('high')
    expect(lookalike.riskLevel).toBe('high')
  })
})

describe('negasi dan bukti sebaya pada pesan', () => {
  it('tidak menghitung permintaan yang dinafikan sebagai permintaan data', () => {
    const result = analyzeMessage(
      'Halo, kami tidak akan pernah meminta KTP, PIN, atau biaya transfer apa pun dari Anda.',
    )

    expect(reasonIds(result)).not.toContain('personal_data_request')
    expect(result.riskLevel).toBe('low')
  })

  it('tetap menangkap "jangan lupa transfer" sebagai permintaan', () => {
    const result = analyzeMessage(
      'Jangan lupa transfer biaya admin 5.000 hari ini juga agar hadiah undian Anda cair.',
    )

    expect(reasonIds(result)).toContain('money_request')
    expect(reasonIds(result)).toContain('prize_fee_combo')
  })

  it('peniadaan yang menempel pada istilah tidak dihitung sebagai klaim', () => {
    const noPrize = analyzeMessage('Kirim biaya admin 150.000 sekarang tanpa hadiah.')

    expect(reasonIds(noPrize)).not.toContain('prize_claim')
    expect(reasonIds(noPrize)).toContain('money_request')

    const noInterest = analyzeMessage('Promo bulan ini: bayar tanpa bunga, cicilan 0 persen.')

    expect(reasonIds(noInterest)).not.toContain('investment_offer')

    const bankInterest = analyzeMessage(
      'Simpan di deposit kami, bunga bank 12% per bulan langsung ke rekening.',
    )

    expect(reasonIds(bankInterest)).toContain('investment_offer')
  })

  it('biaya hadiah yang diperintahkan ke rekening diperkuat, pembayaran lampau tidak', () => {
    const advanceFee = analyzeMessage(
      'Anda terpilih jadi pemenang undian berhadiah Rp10.000.000. Kirim biaya admin 150.000 ke rekening ini.',
    )

    expect(reasonIds(advanceFee)).toContain('prize_fee_combo')
    expect(advanceFee.riskLevel).toBe('high')

    const settled = analyzeMessage(
      'Kak, transfer Rp150.000 sudah saya kirim tadi ya. Terima kasih.',
    )

    expect(reasonIds(settled)).not.toContain('prize_fee_combo')
    expect(settled.riskLevel).toBe('low')
  })

  it('satu kata merek kurir hanya dihitung pada satu bukti', () => {
    const result = analyzeMessage('Kak, paket JNE-nya sudah sampai ya, kurirnya ramah sekali.')

    expect(reasonIds(result)).toContain('courier_context')
    expect(reasonIds(result)).not.toContain('institution_mention')
  })

  it('menilai merek dari alamat tujuan di dalam tautan pesan', () => {
    const result = analyzeMessage(
      'Klik https://situs-casino.online/redirect?url=https://bca-verifikasi-akun.top/login untuk memulihkan akun Anda yang diblokir.',
    )

    expect(reasonIds(result)).toContain('brand_link')
    expect(result.riskLevel).toBe('high')
  })
})

describe('indikasi internal nol: mana yang sah dan mana yang celah mesin', () => {
  it('menangkap merek yang menempel pada kata lain di jalur tautan', () => {
    const result = analyzeLink('https://linktr.ee/bca-verifikasi')

    expect(reasonIds(result)).toContain('brand_path_word')
    expect(result.reasons.find((reason) => reason.id === 'brand_path_word')?.severity).toBe(
      'warning',
    )
    expect(result.riskScore).toBe(18)
    expect(result.riskLevel).toBe('low')
  })

  it('memakai merek yang sama di jalur domain resmi merek itu sendiri tanpa tuduhan', () => {
    const otherBrand = analyzeLink('https://sites.google.com/view/bca-verifikasi-akun/home')

    expect(reasonIds(otherBrand)).toContain('brand_path_word')

    const ownBrand = analyzeLink('https://klikbca.bca.co.id/verifikasi-akun-bca')

    expect(reasonIds(ownBrand)).not.toContain('brand_path_word')
    expect(ownBrand.riskLevel).toBe('low')
  })

  it('tidak menyalahkan slug biasa yang kebetulan memuat nama merek', () => {
    const clean = analyzeLink('https://perpusda.go.id/katalog/buku-permata-biru')

    expect(clean.reasons).toHaveLength(0)
    expect(clean.riskScore).toBe(0)
    expect(clean.riskLevel).toBe('low')

    // Nama merek yang juga kata biasa tidak dihitung bila tidak ada kata
    // login/verifikasi/hadiah di sekitarnya.
    expect(reasonIds(analyzeLink('https://blog.kompas.com/tag/pos-indonesia'))).not.toContain(
      'brand_path_word',
    )
    expect(reasonIds(analyzeLink('https://docs.example.com/panduan-dana-darurat'))).not.toContain(
      'brand_path_word',
    )
    expect(reasonIds(analyzeLink('https://forms.gle/kredinal-bca'))).toContain('brand_path_word')
  })

  it('mengenali varian merek pada label beranda hubung', () => {
    expect(detectBrand('paypa1-secure.com')?.kind).toBe('typosquat')

    const result = analyzeLink('https://paypa1-secure.com/login')

    expect(reasonIds(result)).toContain('brand_typosquat')
    expect(result.riskLevel).toBe('high')
  })

  it('membedakan merek yang ditempel kata permintaan data dari tempelan acak', () => {
    expect(detectBrand('verifikasibca.com')?.gluedContext).toBe('verifikasi')
    expect(detectBrand('xxsicepatxx.com')?.gluedContext).toBeUndefined()

    const glued = analyzeLink('https://verifikasibca.com')

    expect(reasonIds(glued)).toContain('brand_impersonation')
    expect(glued.riskLevel).toBe('medium')
  })

  it('menandai tautan yang memindahkan interaksi ke ruang percakapan', () => {
    const chat = analyzeLink('https://wa.me/6281234567890')

    expect(reasonIds(chat)).toContain('chat_handoff_link')
    expect(chat.riskLevel).toBe('low')

    const chatBot = analyzeLink('https://t.me/verifikasi_bca_bot')

    expect(reasonIds(chatBot)).toContain('chat_handoff_link')
    expect(reasonIds(chatBot)).toContain('brand_path_word')
    expect(chatBot.riskLevel).toBe('medium')
  })

  it('membedakan analisis yang gagal dari hasil berskor nol', () => {
    expect(() => analyzeLink('https://contoh')).toThrow(AnalysisError)

    const zero = analyzeLink('https://www.bca.co.id')

    expect(zero.reasons).toHaveLength(0)
    expect(zero.riskScore).toBe(0)
    expect(zero.riskLevel).toBe('low')
  })
})

describe('kontrak penyimpanan tetap terpenuhi', () => {
  it('hasil analisis baru lolos validasi simpan scan', () => {
    for (const value of [
      'https://example.com/verify?url=https://bca-verifikasi.com/akun',
      'https://www.bca.co.id.verify-secure.top/akun',
      'https://xxsicepatxx.com',
      'https://https-palingsaleh.co/verifikasi-akun',
      'https://linktr.ee/bca-verifikasi',
      'https://wa.me/6281234567890',
      'https://paypa1-secure.com/login',
      'https://verifikasibca.com',
    ]) {
      expect(isScanResult(createScan(analyzeLink(value)))).toBe(true)
    }

    expect(
      isScanResult(
        createScan(
          analyzeMessage(
            'Paket Anda tertahan. Bayar biaya kirim hari ini juga sebelum dibekukan, kirim kode OTP dan foto KTP ke 081234567890 via https://sicepat-paket-tahan.net/resi',
          ),
        ),
      ),
    ).toBe(true)
  })
})

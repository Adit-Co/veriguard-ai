import { readFileSync } from 'node:fs'
import path from 'node:path'
import {
  assertFails,
  assertSucceeds,
  initializeTestEnvironment,
  type RulesTestEnvironment,
} from '@firebase/rules-unit-testing'
import {
  collection,
  collectionGroup,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  limit,
  query,
  serverTimestamp,
  setDoc,
  updateDoc,
  writeBatch,
} from 'firebase/firestore'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'

/**
 * Tes Firestore Rules.
 *
 * Suite ini HANYA berbicara ke emulator Firestore lokal. Sinyalnya adalah variabel
 * FIRESTORE_EMULATOR_HOST yang diisi oleh `firebase emulators:exec`; tanpa itu seluruh test
 * ditandai skip dan TIDAK pernah jatuh ke proyek produksi. Jalankan dari root repository:
 *
 *   npm run test:rules
 *
 * Persyaratan yang tidak bisa dipenuhi repository ini sendiri: JDK (Java 11+) pada PATH
 * dan Firebase CLI. Tanpa keduanya `firebase emulators:exec` tidak dapat memulai emulator,
 * suite ini akan di-skip, dan hasilnya harus dicatat sebagai "belum diverifikasi" —
 * bukan sebagai lulus.
 */

// Vitest dijalankan dengan direktori kerja functions/, jadi rules dibaca dari root repository.
const RULES_FILE = path.resolve(process.cwd(), '..', 'firestore.rules')
const PROJECT_ID = 'demo-veriguard'

const EMULATOR_HOST_AND_PORT = process.env.FIRESTORE_EMULATOR_HOST ?? ''
const EMULATOR_AVAILABLE = EMULATOR_HOST_AND_PORT.length > 0

const [emulatorHost, emulatorPort] = (() => {
  const index = EMULATOR_HOST_AND_PORT.lastIndexOf(':')
  return index === -1
    ? ['127.0.0.1', 8080]
    : [EMULATOR_HOST_AND_PORT.slice(0, index), Number(EMULATOR_HOST_AND_PORT.slice(index + 1))]
})()

const OWNER = 'uid-pemilik'
const OTHER = 'uid-pengguna-lain'
const ADMIN = 'uid-admin'
const URL_HASH = 'a'.repeat(64)
const REPORT_ID = 'b'.repeat(32)

const verified = {
  email_verified: true,
  firebase: { sign_in_provider: 'password' },
} as const
const unverified = {
  email_verified: false,
  firebase: { sign_in_provider: 'password' },
} as const

const profile = {
  uid: OWNER,
  email: 'pemilik@contoh.test',
  displayName: 'Pemilik',
  username: 'pemilik',
  createdAt: '2026-01-01T00:00:00Z',
  lastLoginAt: '2026-01-02T00:00:00Z',
}

// Partisi umpan harian memakai WITA tetap (UTC+8) persis seperti communityDailyFeedDay().
function currentDayId(now = Date.now()): string {
  return String(Math.floor((now + 28_800_000) / 86_400_000))
}

// Batas kirim harian memakai WIB tetap (UTC+7) persis seperti communityDay().
function currentQuotaDayId(now = Date.now()): string {
  return String(Math.floor((now + 25_200_000) / 86_400_000))
}

function yesterdayDayId(): string {
  return currentDayId(Date.now() - 86_400_000)
}

const REPORTER_KEY = 'c'.repeat(64)
const REPORT_PAYLOAD = {
  reporterKey: REPORTER_KEY,
  userName: 'Pemilik (sensor)',
  reportedUrl: 'https://contoh-penipuan.test/hidden',
  hostname: 'contoh-penipuan.test',
  category: 'phishing',
  reason: 'Situs meminta data login bank melalui tautan yang dikirim di pesan.',
} as const

const describeRules = describe.runIf(EMULATOR_AVAILABLE)

let testEnv: RulesTestEnvironment

beforeAll(async () => {
  if (!EMULATOR_AVAILABLE) return
  testEnv = await initializeTestEnvironment({
    projectId: PROJECT_ID,
    firestore: {
      rules: readFileSync(RULES_FILE, 'utf8'),
      host: emulatorHost,
      port: Number(emulatorPort),
    },
  })
})

afterEach(async () => {
  if (!EMULATOR_AVAILABLE) return
  await testEnv.clearFirestore()
})

afterAll(async () => {
  if (!EMULATOR_AVAILABLE) return
  await testEnv.cleanup()
})

describeRules('firestore.rules terhadap emulator', () => {
  it('memuat berkas rules yang sama dengan yang dipakai produksi', () => {
    expect(readFileSync(RULES_FILE, 'utf8')).toContain("rules_version = '2'")
  })

  it('profil hanya terbaca oleh pemilik yang email-nya terkonfirmasi', async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await setDoc(doc(context.firestore(), 'users', OWNER), profile)
    })

    await assertSucceeds(
      getDoc(doc(testEnv.authenticatedContext(OWNER, verified).firestore(), 'users', OWNER)),
    )
    await assertFails(
      getDoc(doc(testEnv.authenticatedContext(OWNER, unverified).firestore(), 'users', OWNER)),
    )
    await assertFails(
      getDoc(doc(testEnv.authenticatedContext(OTHER, verified).firestore(), 'users', OWNER)),
    )
    await assertFails(getDoc(doc(testEnv.unauthenticatedContext().firestore(), 'users', OWNER)))
  })

  it('profil ditolak saat field lebih banyak atau uid tidak cocok', async () => {
    const ownerContext = testEnv.authenticatedContext(OWNER, verified).firestore()

    await assertFails(
      setDoc(doc(ownerContext, 'users', OWNER), { ...profile, role: 'admin' }),
    )
    await assertFails(setDoc(doc(ownerContext, 'users', OWNER), { ...profile, uid: OTHER }))
    await assertFails(
      setDoc(doc(ownerContext, 'users', OWNER), { ...profile, username: 'Nama Tidak Kanon' }),
    )
    await assertSucceeds(setDoc(doc(ownerContext, 'users', OWNER), profile))
  })

  it('riwayat scan adalah milik pemiliknya saja', async () => {
    const scanPath = ['users', OWNER, 'scans', 'scan-1'] as const
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await setDoc(doc(context.firestore(), ...scanPath), { id: 'scan-1' })
    })

    const owner = testEnv.authenticatedContext(OWNER, verified).firestore()
    await assertSucceeds(getDoc(doc(owner, ...scanPath)))
    await assertFails(getDoc(doc(testEnv.authenticatedContext(OTHER, verified).firestore(), ...scanPath)))
    await assertFails(getDoc(doc(testEnv.unauthenticatedContext().firestore(), ...scanPath)))
    // VGL-17: pemangkasan retensi dijalankan dari klien (delete-on-write). Rules harus tetap
    // menolak penghapusan oleh akun lain, oleh pemilik yang belum terverifikasi, dan oleh
    // sesi tanpa login, supaya mekanisme retensi tidak pernah jadi jalur hapus lintas akun.
    await assertFails(
      deleteDoc(doc(testEnv.authenticatedContext(OTHER, verified).firestore(), ...scanPath)),
    )
    await assertFails(
      deleteDoc(doc(testEnv.authenticatedContext(OWNER, unverified).firestore(), ...scanPath)),
    )
    await assertFails(
      deleteDoc(doc(testEnv.unauthenticatedContext().firestore(), ...scanPath)),
    )

    await assertSucceeds(deleteDoc(doc(owner, ...scanPath)))
  })

  // VGL-12: salinan yang dikirim klien adalah hasil penyamaran URL. Bentuknya harus tetap
  // diterima rules produksi, dan tetap ditolak bila field, pemilik, atau status penyamarannya
  // berubah — kalau tidak, riwayat pengguna hilang saat versi terbaru di-deploy.
  it('dokumen hasil penyamaran URL diterima rules dan tetap dijaga bentuknya', async () => {
    const meta = {
      engineVersion: 'test',
      signalCount: 1,
      inputLength: 42,
      aiStatus: 'not_used',
      inputStored: 'redacted',
    }
    const storedScan = (overrides: Record<string, unknown> = {}) => ({
      ownerId: OWNER,
      id: 'scan-1',
      createdAt: '2026-10-31T04:00:00.000Z',
      mode: 'link',
      input: 'https://contoh.test/reset',
      displayTarget: 'contoh.test/reset',
      riskScore: 40,
      riskLevel: 'medium',
      headline: 'Tautan membawa parameter sensitif',
      summary: 'Nilai token disamarkan sebelum disimpan.',
      reasons: [
        {
          id: 'sensitive-query',
          label: 'Parameter token',
          detail: 'Potongan token diganti sebelum masuk penyimpanan.',
          severity: 'warning',
          weight: 20,
          category: 'url-structure',
        },
      ],
      patterns: [],
      recommendations: ['Buka ulang alamat tanpa token.'],
      technical: [{ label: 'Alamat diperiksa', value: 'https://contoh.test/reset' }],
      meta,
      ...overrides,
    })

    const ownerContext = testEnv.authenticatedContext(OWNER, verified).firestore()
    const otherContext = testEnv.authenticatedContext(OTHER, verified).firestore()
    const scanRef = doc(ownerContext, 'users', OWNER, 'scans', 'scan-1')

    await assertSucceeds(setDoc(scanRef, storedScan()))
    await assertFails(setDoc(doc(otherContext, 'users', OWNER, 'scans', 'scan-1'), storedScan()))
    await assertFails(setDoc(scanRef, storedScan({ ownerId: OTHER })))
    await assertFails(setDoc(scanRef, storedScan({ fieldEkstra: true })))
    await assertFails(setDoc(scanRef, storedScan({ meta: { ...meta, inputStored: 'separuh' } })))
    await assertFails(setDoc(scanRef, storedScan({ meta: { ...meta, fieldEkstra: 1 } })))
  })

  it('jalur laporan komunitas lama mati total bahkan untuk pemiliknya', async () => {
    const legacyPath = ['users', OWNER, 'communityReports', 'r1'] as const
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await setDoc(doc(context.firestore(), ...legacyPath), { id: 'r1' })
    })

    await assertFails(getDoc(doc(testEnv.authenticatedContext(OWNER, verified).firestore(), ...legacyPath)))
  })

  it('laporan publik butuh akun terverifikasi dan hash URL yang sah', async () => {
    const reportPath = ['communityReports', URL_HASH, 'reports', REPORT_ID] as const
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await setDoc(doc(context.firestore(), ...reportPath), { id: REPORT_ID })
    })

    await assertSucceeds(
      getDoc(doc(testEnv.authenticatedContext(OTHER, verified).firestore(), ...reportPath)),
    )
    await assertFails(
      getDoc(doc(testEnv.authenticatedContext(OTHER, unverified).firestore(), ...reportPath)),
    )
    // Hash yang bukan 64 digit heksadesimal tidak pernah dapat dibaca, walaupun akunnya sah.
    await assertFails(
      getDoc(
        doc(
          testEnv.authenticatedContext(OTHER, verified).firestore(),
          'communityReports',
          'bukan-hash',
          'reports',
          REPORT_ID,
        ),
      ),
    )
  })

  it('dokumen partisi komunitas dan induknya tidak dapat dibaca maupun ditulis', async () => {
    const partition = doc(testEnv.authenticatedContext(OTHER, verified).firestore(), 'communityReports', URL_HASH)
    await assertFails(getDoc(partition))
    await assertFails(setDoc(partition, { sentinel: true }))
    await assertFails(
      setDoc(
        doc(testEnv.authenticatedContext(OTHER, verified).firestore(), 'communitySummaries', URL_HASH),
        { total: 1 },
      ),
    )
  })

  it('registry username hanya terbuka untuk pemiliknya dan tidak pernah dapat didaftar', async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await setDoc(doc(context.firestore(), 'usernames', 'pemilik'), {
        uid: OWNER,
        createdAt: '2026-01-01T00:00:00Z',
      })
    })

    const usernames = (uid: string) => doc(testEnv.authenticatedContext(uid, verified).firestore(), 'usernames', 'pemilik')
    await assertSucceeds(getDoc(usernames(OWNER)))
    await assertFails(getDoc(usernames(OTHER)))
    await assertFails(
      getDocs(collection(testEnv.authenticatedContext(OWNER, verified).firestore(), 'usernames')),
    )
    await assertFails(
      setDoc(usernames(OWNER), { uid: OWNER, createdAt: '2026-01-01T00:00:00Z' }, { merge: true }),
    )
  })

  it('allowlist admin hanya terbuka untuk dirinya sendiri dan tidak pernah dapat ditulis', async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await setDoc(doc(context.firestore(), 'admins', ADMIN), { active: true, role: 'admin' })
    })

    const firestoreFor = (uid: string) => testEnv.authenticatedContext(uid, verified).firestore()
    // Admin membaca dokumen perannya sendiri: diperlukan untuk memuat status peran.
    await assertSucceeds(getDoc(doc(firestoreFor(ADMIN), 'admins', ADMIN)))
    // Pengguna biasa tidak pernah dapat membaca peran orang lain, termasuk peran admin.
    await assertFails(getDoc(doc(firestoreFor(OWNER), 'admins', ADMIN)))
    await assertFails(getDoc(doc(testEnv.unauthenticatedContext().firestore(), 'admins', ADMIN)))
    // Membaca jalur milik sendiri hanyalah pertanyaan "apakah saya admin?" dan selalu
    // berujung dokumen kosong; ini sengaja diizinkan dan tidak membocorkan orang lain.
    const selfRead = await getDoc(doc(firestoreFor(OWNER), 'admins', OWNER))
    expect(selfRead.exists()).toBe(false)
    // Eskalasi privilise: tidak ada satu pun jalur tulis, juga tidak untuk admin itu sendiri.
    await assertFails(setDoc(doc(firestoreFor(ADMIN), 'admins', ADMIN), { active: true, role: 'admin' }))
    await assertFails(
      setDoc(doc(firestoreFor(OWNER), 'admins', OWNER), { active: true, role: 'admin' }),
    )
    // Daftar admin tidak pernah dapat enumerasi.
    await assertFails(getDocs(collection(firestoreFor(ADMIN), 'admins')))
  })

  it('keputusan moderasi tertutup untuk pengguna biasa dan terbuka untuk admin terdaftar', async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const firestore = context.firestore()
      await setDoc(doc(firestore, 'admins', ADMIN), { active: true, role: 'admin' })
      await setDoc(doc(firestore, 'communityModeration', REPORT_ID), { status: 'pending' })
    })

    const moderationDoc = (uid: string) =>
      doc(testEnv.authenticatedContext(uid, verified).firestore(), 'communityModeration', REPORT_ID)
    await assertSucceeds(getDoc(moderationDoc(ADMIN)))
    await assertFails(getDoc(moderationDoc(OWNER)))
    // Admin yang tidak ada di allowlist, atau ada tetapi tidak aktif, tetap ditolak.
    await assertFails(getDoc(moderationDoc(OTHER)))
  })

  it('kepala umpan global dapat dibaca tetapi tidak dapat didaftar', async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      await setDoc(doc(context.firestore(), 'communityLatestReports', 'global'), {
        entries: [],
        updatedAt: new Date().toISOString(),
      })
    })

    const firestore = testEnv.authenticatedContext(OTHER, verified).firestore()
    await assertSucceeds(getDoc(doc(firestore, 'communityLatestReports', 'global')))
    await assertFails(getDocs(collection(firestore, 'communityLatestReports')))
    await assertFails(
      getDocs(collection(doc(firestore, 'communityLatestReports', 'global'), 'entries')),
    )
  })

  it('umpan harian hanya membuka partisi hari berjalan', async () => {
    const today = currentDayId()
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const firestore = context.firestore()
      await setDoc(doc(firestore, 'communityDailyReports', today, 'reports', REPORT_ID), {
        id: REPORT_ID,
      })
      await setDoc(doc(firestore, 'communityDailyReports', yesterdayDayId(), 'reports', REPORT_ID), {
        id: REPORT_ID,
      })
    })

    const firestore = testEnv.authenticatedContext(OTHER, verified).firestore()
    await assertSucceeds(
      getDoc(doc(firestore, 'communityDailyReports', today, 'reports', REPORT_ID)),
    )
    await assertFails(
      getDoc(doc(firestore, 'communityDailyReports', yesterdayDayId(), 'reports', REPORT_ID)),
    )
    await assertFails(
      getDocs(collection(doc(firestore, 'communityDailyReports', yesterdayDayId()), 'reports')),
    )
  })

  it('penanda harian, kunci pseudonim, dan klaim username tidak dapat disentuh akun lain', async () => {
    const day = currentQuotaDayId()
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const firestore = context.firestore()
      await setDoc(doc(firestore, 'users', OWNER, 'communityReportDays', day), { ownerId: OWNER })
      await setDoc(doc(firestore, 'users', OWNER, 'communityReporterKeys', URL_HASH), {
        ownerId: OWNER,
        reporterKey: REPORTER_KEY,
        createdAt: '2026-01-01T00:00:00Z',
      })
      await setDoc(doc(firestore, 'users', OWNER, 'username', 'current'), {
        username: 'pemilik',
        uid: OWNER,
        createdAt: '2026-01-01T00:00:00Z',
      })
    })

    const owner = testEnv.authenticatedContext(OWNER, verified).firestore()
    const other = testEnv.authenticatedContext(OTHER, verified).firestore()
    const privatePaths = [
      { leaf: 'communityReportDays', id: day },
      { leaf: 'communityReporterKeys', id: URL_HASH },
      { leaf: 'username', id: 'current' },
    ] as const

    for (const { leaf, id } of privatePaths) {
      await assertSucceeds(getDoc(doc(owner, 'users', OWNER, leaf, id)))
      await assertFails(getDoc(doc(other, 'users', OWNER, leaf, id)))
      await assertFails(getDocs(collection(doc(other, 'users', OWNER), leaf)))
      await assertFails(setDoc(doc(other, 'users', OWNER, leaf, id), { sentinel: true }))
      await assertFails(updateDoc(doc(other, 'users', OWNER, leaf, id), { sentinel: true }))
    }

    // Pseudonim dan klaim username tidak dapat diputar bahkan oleh pemiliknya:
    // satu akun hanya menyumbang satu pelapor per URL dan satu nama.
    await assertFails(
      updateDoc(doc(owner, 'users', OWNER, 'communityReporterKeys', URL_HASH), {
        reporterKey: 'd'.repeat(64),
      }),
    )
    await assertFails(deleteDoc(doc(owner, 'users', OWNER, 'username', 'current')))
  })

  it('sesi anonim dengan klaim email terverifikasi tidak pernah dianggap akun nyata', async () => {
    const anonymousWithVerifiedClaim = {
      email_verified: true,
      firebase: { sign_in_provider: 'anonymous' },
    } as const
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const firestore = context.firestore()
      await setDoc(doc(firestore, 'users', OWNER), profile)
      await setDoc(
        doc(firestore, 'communityReports', URL_HASH, 'reports', REPORT_ID),
        { ...REPORT_PAYLOAD, createdAt: new Date(), updatedAt: new Date() },
      )
    })

    const firestore = testEnv.authenticatedContext(OWNER, anonymousWithVerifiedClaim).firestore()
    await assertFails(getDoc(doc(firestore, 'users', OWNER)))
    await assertFails(getDoc(doc(firestore, 'communityReports', URL_HASH, 'reports', REPORT_ID)))
    await assertFails(getDoc(doc(firestore, 'communityLatestReports', 'global')))
    await assertFails(
      getDocs(collection(doc(firestore, 'communityDailyReports', currentDayId()), 'reports')),
    )
  })

  it('laporan tidak dapat dibuat tanpa penanda harian dan kunci pseudonim pengirim', async () => {
    const firestore = testEnv.authenticatedContext(OWNER, verified).firestore()

    await assertFails(
      setDoc(doc(firestore, 'communityReports', URL_HASH, 'reports', REPORT_ID), {
        ...REPORT_PAYLOAD,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      }),
    )
    // Penanda harian sendirian juga ditolak karena laporan sumbernya belum ada.
    await assertFails(
      setDoc(doc(firestore, 'users', OWNER, 'communityReportDays', currentQuotaDayId()), {
        ownerId: OWNER,
        reportId: REPORT_ID,
        urlHash: URL_HASH,
        reporterKey: REPORTER_KEY,
        category: 'phishing',
        createdAt: serverTimestamp(),
      }),
    )
    // Menitipkan pseudonim ke jalur akun lain tetap mustahil.
    await assertFails(
      setDoc(doc(firestore, 'users', OTHER, 'communityReporterKeys', URL_HASH), {
        ownerId: OTHER,
        reporterKey: REPORTER_KEY,
        createdAt: serverTimestamp(),
      }),
    )
  })

  it('alur kirim laporan sah (batch enam dokumen) diterima rules dan terbaca publik', async () => {
    const day = currentQuotaDayId()
    const feedDay = currentDayId()
    const firestore = testEnv.authenticatedContext(OWNER, verified).firestore()
    const batch = writeBatch(firestore)
    batch.set(doc(firestore, 'users', OWNER, 'communityReporterKeys', URL_HASH), {
      ownerId: OWNER,
      reporterKey: REPORTER_KEY,
      createdAt: serverTimestamp(),
    })
    batch.set(doc(firestore, 'users', OWNER, 'communityReportDays', day), {
      ownerId: OWNER,
      reportId: REPORT_ID,
      urlHash: URL_HASH,
      reporterKey: REPORTER_KEY,
      category: 'phishing',
      createdAt: serverTimestamp(),
    })
    batch.set(doc(firestore, 'communityReports', URL_HASH, 'reports', REPORT_ID), {
      ...REPORT_PAYLOAD,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    })
    batch.set(doc(firestore, 'communityLatestReports', 'global', 'entries', REPORT_ID), {
      ...REPORT_PAYLOAD,
      createdAt: serverTimestamp(),
    })
    batch.set(doc(firestore, 'communityDailyReports', feedDay, 'reports', REPORT_ID), {
      userName: REPORT_PAYLOAD.userName,
      reportedUrl: REPORT_PAYLOAD.reportedUrl,
      hostname: REPORT_PAYLOAD.hostname,
      category: REPORT_PAYLOAD.category,
      reason: REPORT_PAYLOAD.reason,
      createdAt: serverTimestamp(),
    })
    batch.set(doc(firestore, 'communityLatestReports', 'global'), {
      entries: [REPORT_ID],
      updatedAt: serverTimestamp(),
    })

    await batch.commit()

    // Laporan yang baru tersimpan memang terbuka untuk akun terverifikasi lain.
    const reader = testEnv.authenticatedContext(OTHER, verified).firestore()
    await assertSucceeds(getDoc(doc(reader, 'communityReports', URL_HASH, 'reports', REPORT_ID)))
    await assertSucceeds(
      getDocs(query(collection(doc(reader, 'communityDailyReports', feedDay), 'reports'), limit(10))),
    )
    // Batas satu laporan per hari ditegakkan: penanda hari yang sama tidak dapat ditimpa.
    await assertFails(
      setDoc(doc(firestore, 'users', OWNER, 'communityReportDays', day), {
        ownerId: OWNER,
        reportId: 'e'.repeat(32),
        urlHash: URL_HASH,
        reporterKey: REPORTER_KEY,
        category: 'phishing',
        createdAt: serverTimestamp(),
      }),
    )
  })

  it('hostname laporan harus menjadi authority URL yang ditampilkan', async () => {
    const day = currentQuotaDayId()
    const feedDay = currentDayId()

    async function commitBatch(payload: typeof REPORT_PAYLOAD) {
      const firestore = testEnv.authenticatedContext(OWNER, verified).firestore()
      const batch = writeBatch(firestore)
      batch.set(doc(firestore, 'users', OWNER, 'communityReporterKeys', URL_HASH), {
        ownerId: OWNER,
        reporterKey: REPORTER_KEY,
        createdAt: serverTimestamp(),
      })
      batch.set(doc(firestore, 'users', OWNER, 'communityReportDays', day), {
        ownerId: OWNER,
        reportId: REPORT_ID,
        urlHash: URL_HASH,
        reporterKey: REPORTER_KEY,
        category: payload.category,
        createdAt: serverTimestamp(),
      })
      batch.set(doc(firestore, 'communityReports', URL_HASH, 'reports', REPORT_ID), {
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      })
      batch.set(doc(firestore, 'communityLatestReports', 'global', 'entries', REPORT_ID), {
        ...payload,
        createdAt: serverTimestamp(),
      })
      batch.set(doc(firestore, 'communityDailyReports', feedDay, 'reports', REPORT_ID), {
        userName: payload.userName,
        reportedUrl: payload.reportedUrl,
        hostname: payload.hostname,
        category: payload.category,
        reason: payload.reason,
        createdAt: serverTimestamp(),
      })
      batch.set(doc(firestore, 'communityLatestReports', 'global'), {
        entries: [REPORT_ID],
        updatedAt: serverTimestamp(),
      })

      return batch.commit().then(() => 'diterima' as const)
    }

    // Port non-default masih authority yang sama, jadi laporan sah tidak ikut ditolak.
    await expect(
      commitBatch({ ...REPORT_PAYLOAD, reportedUrl: 'https://contoh-penipuan.test:8443/hidden' }),
    ).resolves.toBeTruthy()
    await testEnv.clearFirestore()

    // Bentuk host lolos pemeriksaan, tapi host itu bukan pemilik URL yang dilaporkan.
    await expect(commitBatch({ ...REPORT_PAYLOAD, hostname: 'bank-resmi.test' })).rejects.toThrow()
    await testEnv.clearFirestore()

    // Host yang hanya berawalan sama (subdomain pihak lain) juga ditolak.
    await expect(
      commitBatch({ ...REPORT_PAYLOAD, reportedUrl: 'https://contoh-penipuan.test.evil.net/x' }),
    ).rejects.toThrow()
    await testEnv.clearFirestore()

    // Host IPv6 dilewati dari pemeriksaan regex; bentuknya masih harus lolos polanya.
    await expect(
      commitBatch({
        ...REPORT_PAYLOAD,
        hostname: '[2001:db8::1]',
        reportedUrl: 'https://[2001:db8::1]/hidden',
      }),
    ).resolves.toBeTruthy()
  })

  it('keputusan moderasi tertutup untuk pengguna biasa dan butuh batch utuh dari admin', async () => {    await testEnv.withSecurityRulesDisabled(async (context) => {
      await setDoc(doc(context.firestore(), 'admins', ADMIN), { active: true, role: 'admin' })
    })

    const moderation = {
      urlHash: URL_HASH,
      reportId: REPORT_ID,
      status: 'confirmed_malicious',
      note: 'Dikonfirmasi manual oleh moderator.',
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
      updatedBy: ADMIN,
    }
    const nonAdmin = testEnv.authenticatedContext(OWNER, verified).firestore()
    await assertFails(setDoc(doc(nonAdmin, 'communityModeration', REPORT_ID), moderation))
    await assertFails(
      setDoc(doc(nonAdmin, 'communityModerationPublic', REPORT_ID), {
        status: 'confirmed_malicious',
        updatedAt: serverTimestamp(),
      }),
    )

    // Admin menulis tanpa proyeksi publik + entri audit pada permintaan yang sama
    // tetap ditolak, jadi jejak keputusan tidak pernah bolong.
    const admin = testEnv.authenticatedContext(ADMIN, verified).firestore()
    await assertFails(setDoc(doc(admin, 'communityModeration', REPORT_ID), moderation))
    const afterDeny = await getDoc(doc(admin, 'communityModeration', REPORT_ID))
    expect(afterDeny.exists()).toBe(false)
  })

  it('collection-group reports hanya untuk admin, tidak untuk pengguna terverifikasi biasa', async () => {
    await testEnv.withSecurityRulesDisabled(async (context) => {
      const firestore = context.firestore()
      await setDoc(doc(firestore, 'admins', ADMIN), { active: true, role: 'admin' })
      await setDoc(
        doc(firestore, 'communityReports', URL_HASH, 'reports', REPORT_ID),
        { ...REPORT_PAYLOAD, createdAt: new Date(), updatedAt: new Date() },
      )
      await setDoc(
        doc(firestore, 'communityReports', 'f'.repeat(64), 'reports', 'e'.repeat(32)),
        { ...REPORT_PAYLOAD, createdAt: new Date(), updatedAt: new Date() },
      )
    })

    // Pengguna biasa hanya boleh membuka satu partisi URL yang dikenalnya; memetakan
    // seluruh laporan lintas URL adalah eskalasi privilise dan harus ditolak.
    const nonAdmin = testEnv.authenticatedContext(OWNER, verified).firestore()
    await assertFails(getDocs(query(collectionGroup(nonAdmin, 'reports'), limit(10))))

    // Admin memang diberi jalur rekursif untuk antrean moderasi.
    const admin = testEnv.authenticatedContext(ADMIN, verified).firestore()
    const snapshot = await getDocs(query(collectionGroup(admin, 'reports'), limit(10)))
    expect(snapshot.size).toBe(2)
  })

  it('koleksi backend-tepercaya dan jalur yang tidak dikenal selalu ditolak', async () => {
    const firestore = testEnv.authenticatedContext(ADMIN, verified).firestore()
    for (const [collectionName, documentId] of [
      ['communitySummaries', URL_HASH],
      ['communityRateLimits', OWNER],
      ['communityModerationAudit', 'audit-1'],
      ['telemetry', 'apa-pun'],
    ] as const) {
      await assertFails(getDoc(doc(firestore, collectionName, documentId)))
      await assertFails(setDoc(doc(firestore, collectionName, documentId), { sentinel: true }))
    }
  })

  it('sesi anonim tidak pernah mendapat akses ke data pribadi', async () => {
    const guest = testEnv.unauthenticatedContext().firestore()
    await assertFails(getDoc(doc(guest, 'users', OWNER)))
    await assertFails(getDoc(doc(guest, 'communityLatestReports', 'global')))
    await assertFails(
      getDoc(doc(guest, 'communityReports', URL_HASH, 'reports', REPORT_ID)),
    )
  })
})

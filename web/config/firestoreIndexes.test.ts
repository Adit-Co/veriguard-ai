import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

type FieldIndex = {
  order?: string
  queryScope?: string
  arrayConfig?: string
}

type FieldOverride = {
  collectionGroup: string
  fieldPath: string
  indexes: FieldIndex[]
}

type CompositeIndex = {
  collectionGroup: string
  queryScope: string
  fields: { fieldPath: string; order?: string }[]
}

type IndexConfig = {
  indexes: CompositeIndex[]
  fieldOverrides: FieldOverride[]
}

const config = JSON.parse(
  readFileSync(
    fileURLToPath(new URL('../../firestore.indexes.json', import.meta.url)),
    'utf8',
  ),
) as IndexConfig

function mode(index: FieldIndex): string {
  return `${index.queryScope}:${index.order ?? index.arrayConfig ?? ''}`
}

describe('konfigurasi indeks Firestore', () => {
  it('menyediakan indeks collection-group untuk filter reporterKey pada antrean admin', () => {
    const override = config.fieldOverrides.find(
      (entry) =>
        entry.collectionGroup === 'reports' && entry.fieldPath === 'reporterKey',
    )

    expect(override).toBeDefined()
    expect(override?.indexes.map(mode)).toContain('COLLECTION_GROUP:ASCENDING')
    expect(override?.indexes.map(mode)).toContain('COLLECTION:ASCENDING')
    expect(override?.indexes.map(mode)).toContain('COLLECTION:DESCENDING')
  })

  it('mempertahankan indeks produksi communityReports saat indeks baru di-deploy', () => {
    expect(
      config.indexes.some(
        (index) =>
          index.collectionGroup === 'communityReports' &&
          index.queryScope === 'COLLECTION_GROUP' &&
          index.fields.map((field) => field.fieldPath).join(',') ===
            'urlHash,createdAt,__name__',
      ),
    ).toBe(true)

    const createdAtOverride = config.fieldOverrides.find(
      (entry) =>
        entry.collectionGroup === 'communityReports' &&
        entry.fieldPath === 'createdAt',
    )
    expect(createdAtOverride?.indexes.map(mode)).toEqual(
      expect.arrayContaining([
        'COLLECTION:ASCENDING',
        'COLLECTION:DESCENDING',
        'COLLECTION_GROUP:ASCENDING',
        'COLLECTION_GROUP:DESCENDING',
      ]),
    )
  })
})

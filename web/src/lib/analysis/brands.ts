export type BrandCategory = 'bank' | 'wallet' | 'marketplace' | 'courier' | 'social' | 'tech'

export type Brand = {
  name: string
  domain: string
  category: BrandCategory
  aliases?: string[]
}

export const brands: Brand[] = [
  { name: 'bca', domain: 'bca.co.id', category: 'bank', aliases: ['klikbca', 'bankbca'] },
  { name: 'mandiri', domain: 'bankmandiri.co.id', category: 'bank', aliases: ['livin'] },
  { name: 'bri', domain: 'bri.co.id', category: 'bank', aliases: ['brimo'] },
  { name: 'bni', domain: 'bni.co.id', category: 'bank', aliases: ['bnimo'] },
  { name: 'bsi', domain: 'bankbsi.co.id', category: 'bank' },
  { name: 'permata', domain: 'permatabank.com', category: 'bank' },
  { name: 'dana', domain: 'dana.id', category: 'wallet' },
  { name: 'ovo', domain: 'ovo.id', category: 'wallet' },
  { name: 'gopay', domain: 'gopay.co.id', category: 'wallet' },
  { name: 'shopeepay', domain: 'shopeepay.co.id', category: 'wallet' },
  { name: 'shopee', domain: 'shopee.co.id', category: 'marketplace' },
  { name: 'tokopedia', domain: 'tokopedia.com', category: 'marketplace' },
  { name: 'lazada', domain: 'lazada.co.id', category: 'marketplace' },
  { name: 'bukalapak', domain: 'bukalapak.com', category: 'marketplace' },
  { name: 'blibli', domain: 'blibli.com', category: 'marketplace' },
  { name: 'traveloka', domain: 'traveloka.com', category: 'tech' },
  { name: 'tiket', domain: 'tiket.com', category: 'tech' },
  { name: 'gojek', domain: 'gojek.com', category: 'tech' },
  { name: 'grab', domain: 'grab.com', category: 'tech' },
  { name: 'jne', domain: 'jne.co.id', category: 'courier' },
  { name: 'jnt', domain: 'jnt.co.id', category: 'courier', aliases: ['jntexpress'] },
  { name: 'sicepat', domain: 'sicepat.com', category: 'courier' },
  { name: 'pos', domain: 'posindonesia.co.id', category: 'courier', aliases: ['posindonesia'] },
  { name: 'whatsapp', domain: 'whatsapp.com', category: 'social' },
  { name: 'instagram', domain: 'instagram.com', category: 'social' },
  { name: 'facebook', domain: 'facebook.com', category: 'social' },
  { name: 'telegram', domain: 'telegram.org', category: 'social' },
  { name: 'tiktok', domain: 'tiktok.com', category: 'social' },
  { name: 'netflix', domain: 'netflix.com', category: 'tech' },
  { name: 'google', domain: 'google.com', category: 'tech' },
  { name: 'apple', domain: 'apple.com', category: 'tech' },
  { name: 'microsoft', domain: 'microsoft.com', category: 'tech' },
  { name: 'paypal', domain: 'paypal.com', category: 'wallet' },
  { name: 'djp', domain: 'pajak.go.id', category: 'tech', aliases: ['pajak'] },
  { name: 'bpjs', domain: 'bpjs-kesehatan.go.id', category: 'tech' },
  { name: 'pln', domain: 'pln.co.id', category: 'tech' },
  { name: 'telkomsel', domain: 'telkomsel.com', category: 'tech' },
]

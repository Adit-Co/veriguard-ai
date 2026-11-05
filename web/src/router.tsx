import { createBrowserRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import type { RouteObject } from 'react-router-dom'
import { PublicLayout } from './components/layout/PublicLayout'
import { RequireVerifiedEmail } from './components/auth/RequireVerifiedEmail'
import { LandingPage } from './pages/LandingPage'
import { RouteErrorPage } from './pages/RouteErrorPage'
import { lazyPage } from './routerLazy'

const adminDashboardPage = () =>
  import('./pages/AdminDashboardPage').then((module) => ({
    default: module.AdminDashboardPage,
  }))
const articlePage = () =>
  import('./pages/ArticlePage').then((module) => ({ default: module.ArticlePage }))
const communityReportsPage = () =>
  import('./pages/CommunityReportsPage').then((module) => ({
    default: module.CommunityReportsPage,
  }))
const dashboardPage = () =>
  import('./pages/DashboardPage').then((module) => ({ default: module.DashboardPage }))
const educationPage = () =>
  import('./pages/EducationPage').then((module) => ({ default: module.EducationPage }))
const historyPage = () =>
  import('./pages/HistoryPage').then((module) => ({ default: module.HistoryPage }))
const loginPage = () =>
  import('./pages/LoginPage').then((module) => ({ default: module.LoginPage }))
const notFoundPage = () =>
  import('./pages/NotFoundPage').then((module) => ({ default: module.NotFoundPage }))
const registerPage = () =>
  import('./pages/RegisterPage').then((module) => ({ default: module.RegisterPage }))
const resultPage = () =>
  import('./pages/ResultPage').then((module) => ({ default: module.ResultPage }))
const scanPage = () =>
  import('./pages/ScanPage').then((module) => ({ default: module.ScanPage }))
const settingsPage = () =>
  import('./pages/SettingsPage').then((module) => ({ default: module.SettingsPage }))
const verificationEmailPage = () =>
  import('./pages/VerificationEmailPage').then((module) => ({
    default: module.VerificationEmailPage,
  }))

// Fitur yang hanya boleh dipakai akun yang email-nya sudah terkonfirmasi. Tamu (sesi anonim
// atau belum masuk) tetap memakai jalur publik yang sudah ada; halaman verifikasi dan alur
// masuk/daftar sengaja tidak dibungkus supaya pengguna bisa menyelesaikan verifikasinya.
const verifiedOnly = (element: ReactNode) => (
  <RequireVerifiedEmail>{element}</RequireVerifiedEmail>
)

export const appRoutes: RouteObject[] = [
  { index: true, element: <LandingPage /> },
  { path: 'periksa', element: verifiedOnly(lazyPage(scanPage)) },
  { path: 'hasil/:id', element: verifiedOnly(lazyPage(resultPage)) },
  { path: 'komunitas', element: verifiedOnly(lazyPage(communityReportsPage)) },
  { path: 'riwayat', element: verifiedOnly(lazyPage(historyPage)) },
  { path: 'edukasi', element: lazyPage(educationPage) },
  { path: 'edukasi/:slug', element: lazyPage(articlePage) },
  { path: 'masuk', element: lazyPage(loginPage) },
  { path: 'daftar', element: lazyPage(registerPage) },
  { path: 'verifikasi-email', element: lazyPage(verificationEmailPage) },
  { path: 'dashboard', element: verifiedOnly(lazyPage(dashboardPage)) },
  { path: 'dashboard/admin', element: verifiedOnly(lazyPage(adminDashboardPage)) },
  { path: 'pengaturan', element: lazyPage(settingsPage) },
  { path: '*', element: lazyPage(notFoundPage) },
]

export const router = createBrowserRouter([
  {
    path: '/',
    element: <PublicLayout />,
    errorElement: <RouteErrorPage />,
    children: appRoutes,
  },
])

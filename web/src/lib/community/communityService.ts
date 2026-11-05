import * as firestoreBackend from './communityFirestoreService'

/**
 * Jalur aktif hanya Firestore Spark. Daftar global memakai umpan berukuran tetap
 * (`communityLatestReports/global`) sehingga tidak memerlukan kueri lintas partisi
 * atau Cloud Functions. Backend Functions lama tetap tidak dipilih build mana pun.
 */
export const getCommunityContext = firestoreBackend.getCommunityContext
export const listLatestCommunityReports = firestoreBackend.listLatestCommunityReports
export const submitCommunityReport = firestoreBackend.submitCommunityReport

export { CommunityServiceError, communityErrorMessage } from './communityErrors'

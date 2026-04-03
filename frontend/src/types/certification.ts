export type CertStatus = 'studying' | 'passed' | 'failed' | 'abandoned'

export interface CertMaster {
  cerid: string
  cernm: string
  cerct: string
}

export interface OwnCert {
  ownid: string
  ownnm: string
  ownce: string | null
  ownst: CertStatus
  owntg: string | null
  ownhr: number
  owntm: string
  ownup: string
}

export interface CreateCertPayload {
  ownnm: string
  ownce?: string
  ownst: CertStatus
  owntg?: string
  ownhr?: number
}

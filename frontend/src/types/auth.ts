export interface User {
  useid: string
  usenm: string
  useml: string
}

export interface LoginPayload {
  email: string
  password: string
}

export interface SignupPayload {
  email: string
  password: string
  username: string
}

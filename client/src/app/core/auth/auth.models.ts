import type { Permission } from './permissions';

export interface CurrentUser {
  id: string;
  email: string;
  name: string;
  emailVerified: boolean;
  mfaEnabled: boolean;
  roles: string[];
  permissions: Permission[];
  createdAt: number;
}

export interface AuthResponse {
  accessToken: string;
  expiresIn: number;
  user: CurrentUser;
}

export interface MfaChallenge {
  mfaRequired: true;
  mfaToken: string;
}

export type LoginResponse = MfaChallenge | (AuthResponse & { mfaRequired?: false });

export interface ApiErrorBody {
  error: { code: string; message: string; details?: { path: string; message: string }[] };
}

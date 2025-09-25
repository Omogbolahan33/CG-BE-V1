import { User } from '@prisma/client';

export const sanitizeUser = (user: User) => {
  const {
    password,
    verificationOtp,
    verificationOtpExpiry,
    passwordResetOtp,
    passwordResetOtpExpiry,
    ...safeUser
  } = user;
  return safeUser;
};

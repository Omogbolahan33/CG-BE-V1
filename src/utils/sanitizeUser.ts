import { User } from '@prisma/client';
import createDOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';

const window = new JSDOM('').window;
const DOMPurify = createDOMPurify(window);



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


export const sanitize = (input) => DOMPurify.sanitize(input);

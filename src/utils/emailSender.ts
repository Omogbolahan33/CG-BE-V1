/**
 * STUB: Simulates sending a verification email to the user.
 * @param email The recipient's email address.
 * @param otp The 6-digit verification code.
 */
export const sendVerificationEmail = async (email: string, otp: string): Promise<void> => {
    console.log(`EMAIL STUB: Sent verification code ${otp} to ${email}`);
    // TODO: Implement actual email sending logic using Nodemailer or a service like SendGrid
    return Promise.resolve();
};

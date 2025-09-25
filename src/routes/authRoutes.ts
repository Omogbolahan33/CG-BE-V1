import { Router } from 'express';
import { login } from '../controllers/authController';
import { loginRateLimiter } from '../middleware/rateLimiter';

const router = Router();

router.post('/login', loginRateLimiter, login);

export default router;

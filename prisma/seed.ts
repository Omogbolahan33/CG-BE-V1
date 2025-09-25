import { PrismaClient, UserRole, PostCondition, TransactionStatus, DisputeStatus, CategoryType, NotificationType, AdminActionType } from "@prisma/client";
import crypto from "crypto";

const prisma = new PrismaClient();

// Utility to generate random tokens
const generateToken = (): string => crypto.randomBytes(20).toString("hex");

async function main() {
  // ===== USERS =====
  type UserData = {
    username: string;
    email: string;
    password: string;
    role: UserRole;
    isActive: boolean;
    emailVerificationToken?: string;
    resetPasswordToken?: string;
    resetPasswordTokenExpiry?: Date;
    name?: string;
    avatarUrl?: string;
    address?: string;
    city?: string;
    zipCode?: string;
    accountName?: string;
    accountNumber?: string;
    bankName?: string;
  };

  const usersData: UserData[] = [];
  for (let i = 1; i <= 4; i++) {
    usersData.push({
      username: `user${i}`,
      email: `user${i}@example.com`,
      password: `hashedpassword${i}`,
      role: UserRole.Member,
      isActive: true,
      emailVerificationToken: generateToken(),
      resetPasswordToken: generateToken(),
      resetPasswordTokenExpiry: new Date(Date.now() + 24 * 60 * 60 * 1000),
      name: `User ${i}`,
      avatarUrl: `https://i.pravatar.cc/150?img=${i}`,
      address: `Street ${i}`,
      city: `City ${i}`,
      zipCode: `1000${i}`,
      accountName: `User ${i}`,
      accountNumber: `0000${i}`,
      bankName: "Bank Test",
    });
  }

  const users = [];
  for (const u of usersData) {
    users.push(await prisma.user.create({ data: u }));
  }

  // ===== CATEGORIES =====
  type CategoryData = { name: string; description: string; type: CategoryType };
  const categoriesData: CategoryData[] = [];
  for (let i = 1; i <= 4; i++) {
    categoriesData.push({
      name: `Category ${i}`,
      description: `Description for category ${i}`,
      type: i % 2 === 0 ? CategoryType.advert : CategoryType.discussion,
    });
  }

  const categories = [];
  for (const c of categoriesData) {
    categories.push(await prisma.category.create({ data: c }));
  }

  // ===== POSTS =====
  type PostData = {
    title: string;
    content: string;
    isAdvert: boolean;
    price?: number;
    mediaUrl?: string;
    mediaType?: string;
    brand?: string;
    condition?: PostCondition;
    pinnedAt?: Date;
    isCommentingRestricted?: boolean;
    isSold?: boolean;
    authorId: string;
    categoryId: string;
  };

  const postsData: PostData[] = [];
  for (let i = 1; i <= 4; i++) {
    postsData.push({
      title: `Post Title ${i}`,
      content: `Content for post ${i}`,
      isAdvert: i % 2 === 0,
      price: i * 10,
      mediaUrl: `https://picsum.photos/200/300?random=${i}`,
      mediaType: "image",
      brand: `Brand ${i}`,
      condition: PostCondition.New,
      pinnedAt: i % 2 === 0 ? new Date() : undefined,
      isCommentingRestricted: i % 2 === 0,
      isSold: false,
      authorId: users[i - 1].id,
      categoryId: categories[i - 1].id,
    });
  }

  const posts = [];
  for (const p of postsData) {
    posts.push(await prisma.post.create({ data: p }));
  }

  // ===== TRANSACTIONS =====
  type TransactionData = {
    item: string;
    amount: number;
    status: TransactionStatus;
    buyerId: string;
    sellerId: string;
    postId?: string;
    trackingNumber?: string;
    shippingProofUrl?: string;
    shippedAt?: Date;
    deliveredAt?: Date;
  };

  const transactionsData: TransactionData[] = [];
  for (let i = 1; i <= 4; i++) {
    transactionsData.push({
      item: `Item ${i}`,
      amount: i * 20,
      status: TransactionStatus.Pending,
      buyerId: users[i - 1].id,
      sellerId: users[(i % 4)].id,
      postId: posts[i - 1].id,
      trackingNumber: `TRK${i}123`,
      shippingProofUrl: `https://example.com/shipping/${i}`,
      shippedAt: new Date(),
      deliveredAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
    });
  }

  const transactions = [];
  for (const t of transactionsData) {
    transactions.push(await prisma.transaction.create({ data: t }));
  }

  // ===== COMMENTS =====
  type CommentData = {
    content: string;
    mediaUrl?: string;
    mediaType?: string;
    authorId: string;
    postId: string;
  };

  const commentsData: CommentData[] = [];
  for (let i = 1; i <= 4; i++) {
    commentsData.push({
      content: `Comment ${i} on post`,
      mediaUrl: i % 2 === 0 ? `https://picsum.photos/100/100?random=${i}` : undefined,
      mediaType: i % 2 === 0 ? "image" : undefined,
      authorId: users[i - 1].id,
      postId: posts[i - 1].id,
    });
  }

  const comments = [];
  for (const c of commentsData) {
    comments.push(await prisma.comment.create({ data: c }));
  }

  // ===== REVIEWS =====
  type ReviewData = {
    rating: number;
    comment: string;
    isVerifiedPurchase: boolean;
    reviewerId: string;
    userId: string;
    transactionId?: string;
  };

  const reviewsData: ReviewData[] = [];
  for (let i = 1; i <= 4; i++) {
    reviewsData.push({
      rating: 4 + (i % 2),
      comment: `Review ${i}`,
      isVerifiedPurchase: true,
      reviewerId: users[i - 1].id,
      userId: users[(i % 4)].id,
      transactionId: transactions[i - 1].id,
    });
  }

  for (const r of reviewsData) {
    await prisma.review.create({ data: r });
  }

  // ===== NOTIFICATIONS =====
  type NotificationData = {
    type: NotificationType;
    content: string;
    link: string;
    userId: string;
    actorId?: string;
    postId?: string;
    transactionId?: string;
    chatId?: string;
    disputeId?: string;
  };

  const notificationsData: NotificationData[] = [];
  for (let i = 1; i <= 4; i++) {
    notificationsData.push({
      type: NotificationType.follow,
      content: `Notification ${i}`,
      link: `/posts/${posts[i - 1].id}`,
      userId: users[i - 1].id,
      actorId: users[(i % 4)].id,
      postId: posts[i - 1].id,
      transactionId: transactions[i - 1].id,
    });
  }

  for (const n of notificationsData) {
    await prisma.notification.create({ data: n });
  }

  // ===== DISPUTES =====
  type DisputeData = {
    reason: string;
    status: DisputeStatus;
    transactionId: string;
    buyerId: string;
    sellerId: string;
    resolvedByAdminId?: string;
  };

  const disputesData: DisputeData[] = [];
  for (let i = 1; i <= 4; i++) {
    disputesData.push({
      reason: `Dispute reason ${i}`,
      status: DisputeStatus.Open,
      transactionId: transactions[i - 1].id,
      buyerId: transactions[i - 1].buyerId,
      sellerId: transactions[i - 1].sellerId,
      resolvedByAdminId: users[i % 4].id,
    });
  }

  const disputes = [];
  for (const d of disputesData) {
    disputes.push(await prisma.dispute.create({ data: d }));
  }

  // ===== ADMIN ACTIONS =====
  type AdminActionData = {
    action: AdminActionType;
    details?: string;
    originalStatus?: TransactionStatus;
    adminId: string;
    transactionId: string;
  };

  const adminActionsData: AdminActionData[] = [];
  for (let i = 1; i <= 4; i++) {
    adminActionsData.push({
      action: AdminActionType.ForcedPayout,
      details: `Action details ${i}`,
      originalStatus: TransactionStatus.Pending,
      adminId: users[i - 1].id,
      transactionId: transactions[i - 1].id,
    });
  }

  for (const a of adminActionsData) {
    await prisma.adminAction.create({ data: a });
  }

  // ===== ACTIVITY LOGS =====
  type ActivityLogData = { action: string; details: string; userId: string };
  const activityLogsData: ActivityLogData[] = [];
  for (let i = 1; i <= 4; i++) {
    activityLogsData.push({
      action: `Action ${i}`,
      details: `Details for action ${i}`,
      userId: users[i - 1].id,
    });
  }

  for (const al of activityLogsData) {
    await prisma.activityLog.create({ data: al });
  }

  console.log("✅ Full mega-seed complete for all models!");
}

main()
  .catch((e) => console.error(e))
  .finally(async () => {
    await prisma.$disconnect();
  });

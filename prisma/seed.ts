import { PrismaClient, UserRole, PostCondition, TransactionStatus, DisputeStatus, CategoryType, NotificationType, Prisma } from "@prisma/client";
import crypto from "crypto";

const prisma = new PrismaClient();

// Utility to generate random tokens
const generateToken = (): string => crypto.randomBytes(20).toString("hex");

async function main() {
  console.log("🧹 Cleaning database...");
  // Ordered deletion to respect foreign key constraints
  await prisma.notification.deleteMany();
  await prisma.adminAction.deleteMany();
  await prisma.activityLog.deleteMany();
  await prisma.review.deleteMany();
  await prisma.comment.deleteMany();
  await prisma.dispute.deleteMany();
  await prisma.message.deleteMany();
  await prisma.chat.deleteMany();
  await prisma.transaction.deleteMany();
  await prisma.post.deleteMany();
  await prisma.bankAccount.deleteMany();
  await prisma.user.deleteMany();
  await prisma.category.deleteMany();
  console.log("🗑️ Database cleaned.");

  // ===== USERS =====
  console.log("🌱 Seeding users...");
  type UserData = {
    id: string;
    username: string;
    email: string;
    password: string;
    role: UserRole;
    isActive: boolean;
    verificationOtp?: string;
    passwordResetOtp?: string;
    passwordResetOtpExpiry?: Date;
    name?: string;
    avatarUrl?: string;
    address?: string;
    city?: string;
    zipCode?: string;
    isVerified: boolean;
  };

  const usersData: UserData[] = [];
  for (let i = 1; i <= 4; i++) {
    usersData.push({
      id: `user-id-${i}`,
      username: `user${i}`,
      email: `user${i}@example.com`,
      password: `hashedpassword${i}`, // In a real app, this should be properly hashed
      role: i === 1 ? UserRole.Admin : UserRole.Member,
      isActive: true,
      isVerified: i % 2 === 0,
      verificationOtp: generateToken().substring(0, 6),
      passwordResetOtp: generateToken().substring(0, 6),
      passwordResetOtpExpiry: new Date(Date.now() + 15 * 60 * 1000), // OTPs should have a short expiry
      name: `User ${i}`,
      avatarUrl: `https://i.pravatar.cc/150?img=${i}`,
      address: `Street ${i}`,
      city: `City ${i}`,
      zipCode: `1000${i}`,
    });
  }

  const users = [];
  for (const u of usersData) {
    users.push(await prisma.user.create({ data: u }));
  }
  console.log(`👤 Seeded ${users.length} users.`);
  
  // ===== BANK ACCOUNTS =====
  console.log("🌱 Seeding bank accounts...");
  for (let i = 1; i <= 4; i++) {
    await prisma.bankAccount.create({
      data: {
        userId: users[i-1].id,
        accountName: `User ${i}`,
        accountNumber: `012345678${i}`,
        bankName: "Bank Test",
      }
    });
  }
  console.log(`🏦 Seeded bank accounts.`);


  // ===== CATEGORIES =====
  console.log("🌱 Seeding categories...");
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
  console.log(`📚 Seeded ${categories.length} categories.`);

  // ===== POSTS =====
  console.log("🌱 Seeding posts...");
  type PostData = {
    title: string;
    content: string;
    isAdvert: boolean;
    price?: number;
    media?: Prisma.JsonValue;
    brand?: string;
    condition?: PostCondition;
    pinnedAt?: Date;
    isCommentingRestricted?: boolean;
    isSoldOut?: boolean;
    authorId: string;
    categoryId: string;
    lastActivityTimestamp: Date;
  };

  const postsData: PostData[] = [];
  for (let i = 1; i <= 4; i++) {
    const isAdvert = i % 2 === 0;
    postsData.push({
      title: `Post Title ${i}`,
      content: `<p>Content for post ${i}</p>`,
      isAdvert: isAdvert,
      price: isAdvert ? i * 10 : undefined,
      media: {
          type: "image",
          url: `https://picsum.photos/200/300?random=${i}`
      },
      brand: isAdvert ? `Brand ${i}` : undefined,
      condition: isAdvert ? PostCondition.New : undefined,
      pinnedAt: i === 4 ? new Date() : undefined,
      isCommentingRestricted: i === 3,
      isSoldOut: false,
      authorId: users[i - 1].id,
      categoryId: categories[i - 1].id,
      lastActivityTimestamp: new Date(),
    });
  }

  const posts = [];
  for (const p of postsData) {
    posts.push(await prisma.post.create({ data: p as any }));
  }
  console.log(`✍️ Seeded ${posts.length} posts.`);

  // ===== TRANSACTIONS =====
  console.log("🌱 Seeding transactions...");
  type TransactionData = {
    amount: number;
    status: TransactionStatus;
    buyerId: string;
    sellerId: string;
    postId?: string;
    trackingNumber?: string;
    shippingProof?: Prisma.JsonValue;
    shippedAt?: Date;
    deliveredAt?: Date;
  };

  const transactionsData: TransactionData[] = [];
  for (let i = 1; i <= 4; i++) {
    transactionsData.push({
      amount: i * 20,
      status: TransactionStatus.Pending,
      buyerId: users[i - 1].id,
      sellerId: users[(i % 4)].id, // ensures no self-transaction
      postId: posts[i - 1].id,
      trackingNumber: `TRK${i}123`,
      shippingProof: {
          name: "shipping-proof.jpg",
          url: `https://example.com/shipping/${i}`,
          type: "image"
      },
      shippedAt: new Date(),
      deliveredAt: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000),
    });
  }

  const transactions = [];
  for (const t of transactionsData) {
    transactions.push(await prisma.transaction.create({ data: t as any }));
  }
  console.log(`💸 Seeded ${transactions.length} transactions.`);

  // ===== COMMENTS =====
  console.log("🌱 Seeding comments...");
  type CommentData = {
    content: string;
    media?: Prisma.JsonValue;
    authorId: string;
    postId: string;
  };

  const commentsData: CommentData[] = [];
  for (let i = 1; i <= 4; i++) {
    const hasMedia = i % 2 === 0;
    commentsData.push({
      content: `Comment ${i} on post`,
      media: hasMedia ? { type: "image", url: `https://picsum.photos/100/100?random=${i}` } : undefined,
      authorId: users[i - 1].id,
      postId: posts[i - 1].id,
    });
  }

  for (const c of commentsData) {
    await prisma.comment.create({ data: c as any });
  }
  console.log(`💬 Seeded ${commentsData.length} comments.`);

  // ===== REVIEWS =====
  console.log("🌱 Seeding reviews...");
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
  console.log(`⭐ Seeded ${reviewsData.length} reviews.`);

  // ===== NOTIFICATIONS =====
  console.log("🌱 Seeding notifications...");
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
  console.log(`🔔 Seeded ${notificationsData.length} notifications.`);

  // ===== DISPUTES =====
  console.log("🌱 Seeding disputes...");
  type DisputeData = {
    reason: string;
    status: DisputeStatus;
    transactionId: string;
    buyerId: string;
    sellerId: string;
    resolvedByAdminId?: string;
    chatHistory: Prisma.JsonValue;
  };

  const disputesData: DisputeData[] = [];
  for (let i = 1; i <= 4; i++) {
    disputesData.push({
      reason: `Dispute reason ${i}`,
      status: DisputeStatus.Open,
      transactionId: transactions[i - 1].id,
      buyerId: transactions[i - 1].buyerId,
      sellerId: transactions[i - 1].sellerId,
      resolvedByAdminId: users[0].id, // Admin user
      chatHistory: [
        { sender: users[i-1].name, message: `This is the initial reason for dispute ${i}.`, timestamp: new Date().toISOString() }
      ]
    });
  }
  
  for (const d of disputesData) {
    await prisma.dispute.create({ data: d as any });
  }
  console.log(`🛡️ Seeded ${disputesData.length} disputes.`);

  // ===== ADMIN ACTIONS =====
  console.log("🌱 Seeding admin actions...");
  type AdminActionData = {
    action: string;
    details?: string;
    originalStatus?: string;
    adminId: string;
    transactionId: string;
  };

  const adminActionsData: AdminActionData[] = [];
  for (let i = 1; i <= 4; i++) {
    adminActionsData.push({
      action: "Forced Payout",
      details: `Action details ${i}`,
      originalStatus: TransactionStatus.Pending,
      adminId: users[0].id, // Admin user
      transactionId: transactions[i - 1].id,
    });
  }

  for (const a of adminActionsData) {
    await prisma.adminAction.create({ data: a });
  }
  console.log(`⚙️ Seeded ${adminActionsData.length} admin actions.`);

  // ===== ACTIVITY LOGS =====
  console.log("🌱 Seeding activity logs...");
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
  console.log(`📜 Seeded ${activityLogsData.length} activity logs.`);

  console.log("✅ Full seed complete for all models!");
}

main()
  .catch((e) => {
    console.error("An error occurred during seeding:");
    console.error(e);
    // FIX: Cast `process` to `any` to resolve a TypeScript error where 'exit' was not
    // found on the Process type. This is a common issue in environments where Node.js
    // globals are not fully typed, and this script is intended to run in Node.
    (process as any).exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

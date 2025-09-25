
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
    name: string;
    avatarUrl?: string;
    address?: string;
    city?: string;
    zipCode?: string;
    isVerified: boolean;
  };

  const usersData: UserData[] = [];
  // User 1 will be an Admin
  usersData.push({
    id: 'user-id-1',
    username: 'adminuser',
    email: 'admin@example.com',
    password: 'hashedpassword1',
    role: UserRole.Admin,
    isActive: true,
    isVerified: true,
    name: 'Admin User',
    avatarUrl: `https://i.pravatar.cc/150?img=1`,
  });
  for (let i = 2; i <= 4; i++) {
    usersData.push({
      id: `user-id-${i}`,
      username: `user${i}`,
      email: `user${i}@example.com`,
      password: `hashedpassword${i}`,
      role: UserRole.Member,
      isActive: true,
      isVerified: i % 2 === 0,
      verificationOtp: generateToken().substring(0, 6),
      passwordResetOtp: generateToken().substring(0, 6),
      passwordResetOtpExpiry: new Date(Date.now() + 15 * 60 * 1000),
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
  const adminUser = users[0];
  console.log(`👤 Seeded ${users.length} users (1 Admin, 3 Members).`);
  
  // ===== BANK ACCOUNTS =====
  console.log("🌱 Seeding bank accounts...");
  for (const user of users) {
    await prisma.bankAccount.create({
      data: {
        userId: user.id,
        accountName: user.name,
        accountNumber: `012345678${user.id.slice(-1)}`,
        bankName: "Bank Test",
      }
    });
  }
  console.log(`🏦 Seeded ${users.length} bank accounts.`);


  // ===== CATEGORIES =====
  console.log("🌱 Seeding categories...");
  type CategoryData = { name: string; description: string; type: CategoryType };
  const categoriesData: CategoryData[] = [
    { name: 'General Discussion', description: 'Talk about anything.', type: CategoryType.discussion },
    { name: 'Electronics For Sale', description: 'Buy and sell gadgets.', type: CategoryType.advert },
    { name: 'Hobbies', description: 'Share your passions.', type: CategoryType.discussion },
    { name: 'Fashion Market', description: 'Clothing and accessories.', type: CategoryType.advert },
  ];

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
  for (let i = 0; i < 4; i++) {
    const category = categories[i];
    const isAdvert = category.type === 'advert';
    postsData.push({
      title: isAdvert ? `For Sale: Cool Item ${i + 1}` : `Discussion Topic ${i + 1}`,
      content: `<p>This is the full content for post ${i + 1}.</p>`,
      isAdvert: isAdvert,
      price: isAdvert ? (i + 1) * 25.50 : undefined,
      media: {
          type: "image",
          url: `https://picsum.photos/400/300?random=${i}`
      },
      brand: isAdvert ? `Brand ${i + 1}` : undefined,
      condition: isAdvert ? PostCondition.UsedGood : undefined,
      pinnedAt: i === 0 ? new Date() : undefined,
      isCommentingRestricted: i === 3,
      isSoldOut: false,
      authorId: users[i].id,
      categoryId: category.id,
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
  const advertPosts = posts.filter(p => p.isAdvert);
  
  if (advertPosts.length > 0) {
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
      for (let i = 0; i < 2; i++) {
        const post = advertPosts[i];
        if (!post) continue;
        const seller = users.find(u => u.id === post.authorId);
        // Find a buyer who is not the seller
        const buyer = users.find(u => u.id !== seller?.id);
        if (!seller || !buyer) continue;
        
        transactionsData.push({
          amount: post.price!,
          status: TransactionStatus.Pending,
          buyerId: buyer.id,
          sellerId: seller.id,
          postId: post.id,
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
      
      // ===== DISPUTES ===== (only if transactions exist)
      console.log("🌱 Seeding disputes...");
      if (transactions.length > 0) {
        await prisma.dispute.create({
          data: {
            reason: `Dispute reason for first transaction`,
            status: DisputeStatus.Open,
            transactionId: transactions[0].id,
            buyerId: transactions[0].buyerId,
            sellerId: transactions[0].sellerId,
            resolvedByAdminId: adminUser.id, // Correctly assign admin user
            chatHistory: [
              { sender: users.find(u => u.id === transactions[0].buyerId)!.name, message: `This is the initial reason.`, timestamp: new Date().toISOString() }
            ]
          }
        });
        console.log(`🛡️ Seeded 1 dispute.`);
      }
      
      // ===== ADMIN ACTIONS ===== (only if transactions exist)
      console.log("🌱 Seeding admin actions...");
       if (transactions.length > 0) {
        await prisma.adminAction.create({
          data: {
            action: "Forced Payout", // Use a string as per schema
            details: `Action details for transaction 1`,
            originalStatus: "Pending", // FIX: Changed from enum to string literal to match schema
            adminId: adminUser.id, // Correctly assign admin user
            transactionId: transactions[0].id,
          }
        });
        console.log(`⚙️ Seeded 1 admin action.`);
      }

       // ===== REVIEWS ===== (only if transactions exist)
      console.log("🌱 Seeding reviews...");
      if (transactions.length > 0) {
        await prisma.review.create({
          data: {
            rating: 5,
            comment: `Great transaction!`,
            isVerifiedPurchase: true,
            reviewerId: transactions[0].buyerId,
            userId: transactions[0].sellerId,
            transactionId: transactions[0].id,
          }
        });
        console.log(`⭐ Seeded 1 review.`);
      }
  }


  // ===== COMMENTS =====
  console.log("🌱 Seeding comments...");
  type CommentData = {
    content: string;
    media?: Prisma.JsonValue;
    authorId: string;
    postId: string;
  };

  const commentsData: CommentData[] = [];
  for (let i = 0; i < 4; i++) {
    const hasMedia = i % 2 === 0;
    commentsData.push({
      content: `Comment ${i+1} on post`,
      media: hasMedia ? { type: "image", url: `https://picsum.photos/100/100?random=${i}` } : Prisma.JsonNull,
      authorId: users[i].id,
      postId: posts[i].id,
    });
  }

  for (const c of commentsData) {
    await prisma.comment.create({ data: c as any });
  }
  console.log(`💬 Seeded ${commentsData.length} comments.`);

  // ===== NOTIFICATIONS =====
  console.log("🌱 Seeding notifications...");
  type NotificationData = {
    type: NotificationType;
    content: string;
    link: string;
    userId: string;
    actorId?: string;
    postId?: string;
  };

  const notificationsData: NotificationData[] = [];
  for (let i = 1; i < 4; i++) {
    notificationsData.push({
      type: NotificationType.follow,
      content: `User ${users[i].name} started following you.`,
      link: `/profile/${users[i].id}`,
      userId: users[0].id, // Notify the admin
      actorId: users[i].id,
      postId: posts[i].id,
    });
  }

  for (const n of notificationsData) {
    await prisma.notification.create({ data: n });
  }
  console.log(`🔔 Seeded ${notificationsData.length} notifications.`);
  
  // ===== ACTIVITY LOGS =====
  console.log("🌱 Seeding activity logs...");
  type ActivityLogData = { action: string; details: string; userId: string };
  const activityLogsData: ActivityLogData[] = [];
  for (let i = 0; i < 4; i++) {
    activityLogsData.push({
      action: `Created Post`,
      details: `User created post "${posts[i].title}"`,
      userId: users[i].id,
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
    (process as any).exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

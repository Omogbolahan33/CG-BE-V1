import {
  PrismaClient,
  UserRole,
  CategoryType,
  PostCondition,
  TransactionStatus,
  DisputeStatus,
  UserReportStatus,
  NotificationType,
  Prisma,
  User,
  Category,
  Post,
} from '@prisma/client';
import crypto from 'crypto';

const prisma = new PrismaClient();

// Helper functions
const generateToken = (): string => crypto.randomBytes(20).toString('hex');
const getRandomItem = <T>(arr: T[]): T => arr[Math.floor(Math.random() * arr.length)];
const getRandomSubset = <T>(arr: T[], maxCount: number): T[] => {
    const shuffled = [...arr].sort(() => 0.5 - Math.random());
    return shuffled.slice(0, Math.floor(Math.random() * (maxCount + 1)));
};
const LOREM_IPSUM_SHORT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.";
const generateRandomText = (wordCount: number): string => {
    const words = LOREM_IPSUM_SHORT.replace(/[.,]/g, '').split(' ');
    let text = Array.from({ length: wordCount }, () => getRandomItem(words)).join(' ');
    return text.charAt(0).toUpperCase() + text.slice(1) + '.';
};
const generateRandomHtml = (paragraphCount: number): string => {
    let html = '';
    for (let i = 0; i < paragraphCount; i++) {
        html += `<p>${generateRandomText(Math.floor(Math.random() * 40) + 15)}</p>`;
    }
    return html;
};
const timeAgo = (days: number): Date => {
    const date = new Date();
    date.setDate(date.getDate() - (Math.random() * days));
    return date;
};

async function main() {
    console.log(`🧹 Cleaning database...`);
    // Delete in order of dependency to avoid foreign key constraint errors
    await prisma.notification.deleteMany();
    await prisma.adminAction.deleteMany();
    await prisma.message.deleteMany();
    await prisma.chat.deleteMany();
    await prisma.review.deleteMany();
    await prisma.dispute.deleteMany();
    await prisma.userReport.deleteMany();
    await prisma.activityLog.deleteMany();
    await prisma.comment.deleteMany();
    await prisma.transaction.deleteMany();
    await prisma.post.deleteMany();
    await prisma.bankAccount.deleteMany();
    await prisma.user.deleteMany(); 
    await prisma.category.deleteMany();
    await prisma.marketplacePartner.deleteMany();
    await prisma.backofficeSettings.deleteMany();
    console.log(`🗑️ Database cleaned.`);

    console.log(`🌱 Seeding global settings...`);
    await prisma.backofficeSettings.create({
        data: {
            maintenanceMode: false,
            enablePostCreation: true,
            enableAdvertisements: true,
            enablePayments: true,
            enableSignups: true,
            enableLogins: true,
            enableCommenting: true,
            enableLikes: true,
            enableFollowing: true,
            enableChats: true,
            enableCalling: true,
            enableDisputes: true,
        },
    });

    const mockPartners = [
      {
        id: 'gig', name: 'GIG Logistics', logoUrl: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgNDAiPjx0ZXh0IHg9IjUwIiB5PSIyMyIgc3R5bGU9ImZvbnQ6Ym9sZCAyMHB4IHNhbnMtc2VyaWY7dGV4dC1hbmNob3I6bWlkZGxlO2ZpbGw6IzA2YjE0MiI+R0lHPC90ZXh0Pjx0ZXh0IHg9IjUwIiB5PSIzNiIgc3R5bGU9ImZvbnQ6N3B4IHNhbnMtc2VyaWY7dGV4dC1hbmNob3I6bWlkZGxlO2ZpbGw6I2U1NjI0ZCI+TG9naXN0aWNzPC90ZXh0Pjwvc3ZnPg==',
        services: [ { id: 'gig-bike', name: 'Standard Bike', method: 'Bike', deliveryDurationDays: 2, fee: 3500 }, { id: 'gig-van', name: 'Medium Van', method: 'Van', deliveryDurationDays: 3, fee: 8000 }, { id: 'gig-air', name: 'Express Air', method: 'Air', deliveryDurationDays: 1, fee: 15000 }, ]
      },
      {
        id: 'kwik', name: 'Kwik Delivery', logoUrl: 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxMDAgNDAiPjx0ZXh0IHg9IjUiIHk9IjMwIiBzdHlsZT0iZm9udDpib2xkIDI4cHggbW9ub3NwYWNlO2ZpbGw6IzAwMDAwMCI+S3dpay48L3RleHQ+PC9zdmc+',
        services: [ { id: 'kwik-4hr', name: '4-Hour Bike', method: 'Bike', deliveryDurationDays: 1, fee: 2500 }, { id: 'kwik-car', name: 'Kwik Car', method: 'Car', deliveryDurationDays: 1, fee: 5000 }, ]
      },
    ];
    await prisma.marketplacePartner.createMany({
        data: mockPartners.map(p => ({
            ...p,
            services: p.services as any,
        })),
    });
    console.log(`🌍 Global settings seeded.`);

    console.log(`👤 Seeding users...`);
    const usersData: Prisma.UserCreateInput[] = [
        { id: 'user-01', username: 'superadmin', password: 'password', email: 'superadmin@market.com', role: UserRole.SuperAdmin, name: 'Super Admin User', avatarUrl: 'https://i.pravatar.cc/150?u=superadmin', isVerified: true, isActive: true },
        { id: 'user-08', username: 'admin2', password: 'password', email: 'admin2@market.com', role: UserRole.Admin, name: 'Admin Two', avatarUrl: 'https://i.pravatar.cc/150?u=admin2', isVerified: true, isActive: true },
        { id: 'user-02', username: 'alice', password: 'password', email: 'alice@example.com', role: UserRole.Member, name: 'Alice', avatarUrl: 'https://i.pravatar.cc/150?u=alice', isVerified: true, isActive: true },
        { id: 'user-03', username: 'anonymouspanda', password: 'password', email: 'panda@example.com', role: UserRole.Member, name: 'AnonymousPanda', avatarUrl: 'https://i.pravatar.cc/150?u=panda', isVerified: false, isActive: true },
        { id: 'user-04', username: 'anonymousfox', password: 'password', email: 'fox@example.com', role: UserRole.Member, name: 'AnonymousFox', avatarUrl: 'https://i.pravatar.cc/150?u=fox', isVerified: false, isActive: false },
        { id: 'user-05', username: 'anonymoustiger', password: 'password', email: 'tiger@example.com', role: UserRole.Member, name: 'AnonymousTiger', avatarUrl: 'https://i.pravatar.cc/150?u=tiger', isVerified: false, isActive: true, banExpiresAt: new Date(Date.now() + 3 * 24 * 60 * 60 * 1000), banReason: 'Spamming', banStartDate: new Date() },
        { id: 'user-06', username: 'bob', password: 'password', email: 'bob@example.com', role: UserRole.Member, name: 'Bob', avatarUrl: 'https://i.pravatar.cc/150?u=bob', isVerified: true, isActive: true },
        { id: 'user-07', username: 'charlie', password: 'password', email: 'charlie@example.com', role: UserRole.Member, name: 'Charlie', avatarUrl: 'https://i.pravatar.cc/150?u=charlie', isVerified: false, isActive: true },
    ];

    for (let i = 0; i < 50; i++) {
        const name = `user${i+10}`;
        usersData.push({
            username: name,
            password: 'password',
            email: `${name}@example.com`,
            role: 'Member',
            name: `User ${i+10}`,
            avatarUrl: `https://i.pravatar.cc/150?u=${name}`,
            isActive: Math.random() > 0.1,
            isVerified: Math.random() > 0.3,
            verificationOtp: generateToken(),
            verificationOtpExpiry: timeAgo(-1), // in the future
        });
    }

    for (const u of usersData) {
      await prisma.user.create({ data: u });
    }
    const users = await prisma.user.findMany();
    console.log(`👥 ${users.length} users seeded.`);

    // Seed some bank accounts
    const usersWithBankAccounts = getRandomSubset(users, 30);
    for (const user of usersWithBankAccounts) {
        await prisma.bankAccount.create({
            data: {
                userId: user.id,
                accountName: user.name,
                accountNumber: String(Math.floor(1000000000 + Math.random() * 9000000000)),
                bankName: getRandomItem(['First Bank', 'UBA', 'GTBank', 'Access Bank']),
            }
        });
    }
    console.log(`🏦 Bank accounts seeded.`);
    
    // Seed social graph
    for (const user of users) {
        const usersToFollow = getRandomSubset(users.filter(u => u.id !== user.id), 20);
        const usersToBlock = getRandomSubset(users.filter(u => u.id !== user.id), 2);
        await prisma.user.update({
            where: { id: user.id },
            data: {
                following: { connect: usersToFollow.map(u => ({ id: u.id })) },
                blockedUsers: { connect: usersToBlock.map(u => ({ id: u.id })) },
            }
        });
    }
    console.log(`🕸️ Social graph seeded.`);

    console.log(`📚 Seeding categories...`);
    const mockCategoriesData = [
        // Discussion Categories
        { id: 'cat-disc-01', name: 'General Discussion', description: 'Talk about anything and everything.', type: 'discussion' },
        { id: 'cat-disc-02', name: 'Technology', description: 'Gadgets, software, and the future.', type: 'discussion' },
        { id: 'cat-disc-03', name: 'Gaming', description: 'Video games, board games, and gaming culture.', type: 'discussion' },
        // Advert Categories
        { id: 'cat-sale-elec-01', name: 'Computers & Laptops', description: 'Desktops, laptops, and components.', type: 'advert' },
        { id: 'cat-sale-elec-02', name: 'Phones & Accessories', description: 'Smartphones, cases, chargers, and more.', type: 'advert' },
        { id: 'cat-sale-home-01', name: 'Furniture', description: 'Sofas, tables, chairs, and bedroom sets.', type: 'advert' },
    ];
     await prisma.category.createMany({
        data: mockCategoriesData.map(c => ({
            id: c.id,
            name: c.name,
            description: c.description,
            type: c.type as CategoryType,
        }))
    });
    const categories = await prisma.category.findMany();
    console.log(`📖 ${categories.length} categories seeded.`);
    
    console.log(`✍️ Seeding posts and comments...`);
    const discussionCategories = categories.filter(c => c.type === 'discussion');
    const advertCategories = categories.filter(c => c.type === 'advert');
    
    for (let i = 0; i < 250; i++) {
        const isAdvert = Math.random() > 0.4;
        const author = isAdvert ? getRandomItem(usersWithBankAccounts) : getRandomItem(users);
        const category = isAdvert ? getRandomItem(advertCategories) : getRandomItem(discussionCategories);
        const likedByUsers = getRandomSubset(users, 30);
        
        const postData: Prisma.PostCreateInput = {
            title: generateRandomText(Math.floor(Math.random() * 8) + 5),
            content: generateRandomHtml(Math.floor(Math.random() * 3) + 1),
            author: { connect: { id: author.id } },
            category: { connect: { id: category.id } },
            isAdvert: isAdvert,
            timestamp: timeAgo(60),
            lastActivityTimestamp: new Date(),
            likedBy: { connect: likedByUsers.map(u => ({ id: u.id })) },
            isCommentingRestricted: Math.random() > 0.95,
            isSoldOut: false,
        };

        if(isAdvert) {
            postData.price = parseFloat((Math.random() * 100000 + 1000).toFixed(2));
            postData.quantity = Math.floor(Math.random() * 50) + 1;
            postData.condition = getRandomItem(['New', 'UsedLikeNew', 'UsedGood', 'UsedFair']) as PostCondition;
            postData.brand = getRandomItem(['Apple', 'Samsung', 'Nike', 'Handmade', 'Generic']);
            postData.media = {
                type: 'image',
                url: `https://picsum.photos/seed/${i}/800/600`,
            } as Prisma.JsonObject;
        }
        
        const post = await prisma.post.create({ data: postData });

        // Seed comments
        const numComments = Math.floor(Math.random() * 30);
        for(let j=0; j < numComments; j++) {
            const commentAuthor = getRandomItem(users);
            const commentLikedBy = getRandomSubset(users, 15);
            
            const comment = await prisma.comment.create({
                data: {
                    content: generateRandomText(Math.floor(Math.random() * 25) + 5),
                    author: { connect: { id: commentAuthor.id } },
                    post: { connect: { id: post.id } },
                    likedBy: { connect: commentLikedBy.map(u => ({ id: u.id })) },
                }
            });

            // Seed replies
            if (Math.random() > 0.5) {
                const numReplies = Math.floor(Math.random() * 4);
                let parentId = comment.id;
                for(let k=0; k < numReplies; k++) {
                    const replyAuthor = getRandomItem(users);
                    const reply = await prisma.comment.create({
                        data: {
                            content: generateRandomText(Math.floor(Math.random() * 15) + 3),
                            author: { connect: { id: replyAuthor.id } },
                            post: { connect: { id: post.id } },
                            parent: { connect: { id: parentId } }
                        }
                    });
                    // a small chance of deeper nesting
                    if (Math.random() > 0.7) {
                        parentId = reply.id;
                    }
                }
            }
        }
    }
    const postCount = await prisma.post.count();
    const commentCount = await prisma.comment.count();
    console.log(`📝 ${postCount} posts and ${commentCount} comments seeded.`);

    console.log(`💰 Seeding transactions...`);
    const advertPosts = await prisma.post.findMany({ where: { isAdvert: true }});
    for (let i = 0; i < 80; i++) {
        const post = getRandomItem(advertPosts);
        const seller = users.find(u => u.id === post.authorId);
        const buyer = getRandomItem(users.filter(u => u.id !== post.authorId));
        if (!seller || !buyer) continue;
        
        const status = getRandomItem(['Pending', 'Completed', 'InEscrow', 'Shipped', 'Delivered', 'Disputed', 'Cancelled']) as TransactionStatus;
        
        const transaction = await prisma.transaction.create({
            data: {
                post: { connect: { id: post.id } },
                buyer: { connect: { id: buyer.id } },
                seller: { connect: { id: seller.id } },
                amount: post.price || 0,
                status: status,
                date: timeAgo(30)
            }
        });
        
        if (status === 'Completed' && Math.random() > 0.3) {
             await prisma.review.create({
                data: {
                    rating: Math.floor(Math.random() * 5) + 1,
                    comment: generateRandomText(15),
                    isVerifiedPurchase: true,
                    reviewer: { connect: { id: buyer.id } },
                    user: { connect: { id: seller.id } },
                    transaction: { connect: { id: transaction.id } }
                }
            });
        }

        if (status === 'Disputed') {
             await prisma.dispute.create({
                data: {
                    transaction: { connect: { id: transaction.id } },
                    buyer: { connect: { id: transaction.buyerId } },
                    seller: { connect: { id: transaction.sellerId } },
                    reason: 'Item not as described.',
                    status: 'Open',
                    chatHistory: [{ sender: buyer.name, message: generateRandomText(10), timestamp: new Date().toISOString() }] as any,
                }
            });
        }
    }
    const transactionCount = await prisma.transaction.count();
    console.log(`💸 ${transactionCount} transactions seeded.`);

    console.log(`✅ Seeding finished successfully!`);
}

main()
  .catch((e) => {
    console.error(e);
    // process.exit(1) can cause issues in some environments.
    // Throwing the error is usually sufficient.
    throw e;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

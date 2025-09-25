/**
 * @file seed.ts
 * @description This script populates the Social Marketplace database with a rich set of mock data.
 * It's designed to be run with `prisma db seed` and will fill all tables according to the schema
 * defined in `Documentations/prisma.ts`. This allows for a fully functional development and
 * testing environment that mirrors a live application.
 *
 * ---
 * 🚀 HOW TO RUN THIS SEED SCRIPT 🚀
 * ---
 * This script is configured to work with a Prisma setup connected to a Supabase PostgreSQL database,
 * running from a development environment like GitHub Codespaces.
 *
 * 1. SETUP YOUR ENVIRONMENT:
 *    - Ensure you have a `.env` file in your project root.
 *    - Add your Supabase Database URL to it. It should look like this:
 *      `DATABASE_URL="postgresql://postgres:[YOUR-PASSWORD]@[YOUR-SUPABASE-HOST]:5432/postgres"`
 *
 * 2. INSTALL DEPENDENCIES:
 *    - Make sure you have Prisma and TypeScript dependencies installed:
 *      `npm install prisma typescript ts-node @types/node --save-dev`
 *      `npm install @prisma/client`
 *
 * 3. CONFIGURE `package.json`:
 *    - Add the following script to your `package.json` to tell Prisma how to run this seed file:
 *      ```json
 *      "prisma": {
 *        "seed": "ts-node --compiler-options '{\\\"module\\\":\\\"CommonJS\\\"}' seed.ts"
 *      }
 *      ```
 *
 * 4. MIGRATE YOUR DATABASE:
 *    - Push your schema to the Supabase database to create the tables.
 *      `npx prisma db push`
 *
 * 5. RUN THE SEED SCRIPT:
 *    - Execute the seed command from your terminal.
 *      `npx prisma db seed`
 *
 *    - This will run the `main()` function below, populating your database.
 *      You can monitor the progress in your terminal.
 */

import { PrismaClient, Prisma, UserRole, PostCondition, CategoryType, TransactionStatus, DisputeStatus, UserReportStatus, NotificationType } from '@prisma/client';
import { mockUsers, mockCategories, mockPosts, mockTransactions, mockDisputes, mockMarketplacePartners, mockUserReports } from './constants';

const prisma = new PrismaClient();

// A simple hashing function for mock passwords.
// In a real application, you MUST use a strong hashing algorithm like bcrypt.
const simpleHash = (password: string) => `hashed_${password}`;

async function main() {
    console.log("--- Starting the seeding process ---");

    // 1. Clean up existing data to ensure a fresh start
    console.log("🧹 Clearing existing data...");
    await prisma.notification.deleteMany();
    await prisma.message.deleteMany();
    await prisma.chat.deleteMany();
    await prisma.adminAction.deleteMany();
    await prisma.dispute.deleteMany();
    await prisma.review.deleteMany();
    await prisma.transaction.deleteMany();
    await prisma.comment.deleteMany();
    await prisma.post.deleteMany();
    await prisma.category.deleteMany();
    await prisma.userReport.deleteMany();
    await prisma.activityLog.deleteMany();
    await prisma.bankAccount.deleteMany();
    await prisma.user.deleteMany();
    await prisma.marketplacePartner.deleteMany();
    await prisma.backofficeSettings.deleteMany();
    console.log("✅ Existing data cleared.");

    // 2. Seed Backoffice Settings (Singleton)
    console.log("⚙️ Seeding backoffice settings...");
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
    console.log("✅ Backoffice settings seeded.");

    // 3. Seed Marketplace Partners
    console.log("🚚 Seeding marketplace partners...");
    await prisma.marketplacePartner.createMany({
        data: mockMarketplacePartners.map(p => ({
            id: p.id,
            name: p.name,
            logoUrl: p.logoUrl,
            services: p.services as unknown as Prisma.JsonValue,
        })),
    });
    console.log("✅ Marketplace partners seeded.");

    // 4. Seed Categories
    console.log("📚 Seeding categories...");
    await prisma.category.createMany({
        data: mockCategories.map(c => ({
            id: c.id,
            name: c.name,
            description: c.description,
            type: c.type === 'advert' ? CategoryType.advert : CategoryType.discussion,
        })),
    });
    console.log("✅ Categories seeded.");
    
    // 5. Seed Users
    console.log("👤 Seeding users...");
    const userCreatePromises = mockUsers.map(user =>
        prisma.user.create({
            data: {
                id: user.id,
                username: user.username,
                password: simpleHash(user.password),
                email: user.email,
                role: user.role === 'Super Admin' ? UserRole.SuperAdmin : user.role === 'Admin' ? UserRole.Admin : UserRole.Member,
                name: user.name,
                avatarUrl: user.avatarUrl,
                address: user.address,
                city: user.city,
                zipCode: user.zipCode,
                isActive: user.isActive,
                banExpiresAt: user.banExpiresAt ? new Date(user.banExpiresAt) : null,
                banReason: user.banReason,
                banStartDate: user.banStartDate ? new Date(user.banStartDate) : null,
                isVerified: user.isVerified,
                lastSeen: user.lastSeen ? new Date(user.lastSeen) : new Date(),
                bankAccount: user.bankAccount ? {
                    create: {
                        accountName: user.bankAccount.accountName,
                        accountNumber: user.bankAccount.accountNumber,
                        bankName: user.bankAccount.bankName,
                    }
                } : undefined,
            }
        })
    );
    const createdUsers = await Promise.all(userCreatePromises);
    const userMap = new Map(createdUsers.map(u => [u.username, u]));
    console.log(`✅ ${createdUsers.length} users seeded.`);

    // 6. Seed User Relationships (Follows)
    console.log("🤝 Seeding user relationships...");
    const followUpdatePromises = mockUsers.map(user => {
        if (user.followingIds.length > 0) {
            const userToUpdate = userMap.get(user.username);
            if(userToUpdate) {
                return prisma.user.update({
                    where: { id: userToUpdate.id },
                    data: {
                        following: {
                            connect: user.followingIds.map(followingName => ({ username: mockUsers.find(u => u.id === followingName)?.username })).filter(Boolean) as Prisma.UserWhereUniqueInput[]
                        }
                    }
                });
            }
        }
        return null;
    }).filter(Boolean);
    await Promise.all(followUpdatePromises);
    console.log("✅ User relationships seeded.");
    
    // 7. Seed Posts and their nested Comments
    console.log("📄 Seeding posts and comments...");
    for (const post of mockPosts) {
        const author = userMap.get(mockUsers.find(u => u.name === post.author)!.username);
        if (!author) continue;

        const createdPost = await prisma.post.create({
            data: {
                id: post.id,
                title: post.title,
                content: post.content,
                timestamp: new Date(post.timestamp),
                lastActivityTimestamp: new Date(post.lastActivityTimestamp),
                isAdvert: post.isAdvert,
                price: post.price,
                isSoldOut: post.isSoldOut,
                quantity: post.quantity,
                brand: post.brand,
                condition: post.condition ? post.condition.replace(/Used - /g, 'Used').replace(' ', '') as PostCondition : null,
                deliveryOptions: post.deliveryOptions as unknown as Prisma.JsonValue,
                pinnedAt: post.pinnedAt ? new Date(post.pinnedAt) : null,
                isCommentingRestricted: post.isCommentingRestricted,
                media: post.media as unknown as Prisma.JsonValue,
                author: { connect: { id: author.id } },
                category: { connect: { id: post.categoryId } },
                likedBy: {
                    connect: post.likedBy.map(userId => ({ id: userId }))
                },
            }
        });

        // Seed comments for this post
        for (const comment of post.comments) {
            const commentAuthor = userMap.get(mockUsers.find(u => u.name === comment.author)!.username);
            if (!commentAuthor) continue;

            const createdComment = await prisma.comment.create({
                data: {
                    id: comment.id,
                    content: comment.content,
                    timestamp: new Date(comment.timestamp),
                    author: { connect: { id: commentAuthor.id } },
                    post: { connect: { id: createdPost.id } },
                    likedBy: {
                        connect: comment.likedBy.map(userId => ({ id: userId }))
                    }
                }
            });

            // Seed replies for this comment
            for (const reply of comment.replies) {
                const replyAuthor = userMap.get(mockUsers.find(u => u.name === reply.author)!.username);
                if (!replyAuthor) continue;
                await prisma.comment.create({
                     data: {
                        id: reply.id,
                        content: reply.content,
                        timestamp: new Date(reply.timestamp),
                        author: { connect: { id: replyAuthor.id } },
                        post: { connect: { id: createdPost.id } },
                        parent: { connect: { id: createdComment.id } },
                    }
                });
            }
        }
    }
    console.log("✅ Posts and comments seeded.");

    // 8. Seed Transactions
    console.log("💳 Seeding transactions...");
    for (const tx of mockTransactions) {
        const buyer = userMap.get(mockUsers.find(u => u.name === tx.buyer)!.username);
        const seller = userMap.get(mockUsers.find(u => u.name === tx.seller)!.username);
        if (!buyer || !seller) continue;
        
        await prisma.transaction.create({
            data: {
                id: tx.id,
                status: tx.status.replace(' ', '') as TransactionStatus,
                date: new Date(tx.date),
                amount: tx.amount,
                deliveryFee: tx.deliveryFee,
                shippedAt: tx.shippedAt ? new Date(tx.shippedAt) : null,
                deliveredAt: tx.deliveredAt ? new Date(tx.deliveredAt) : null,
                completedAt: tx.completedAt ? new Date(tx.completedAt) : null,
                cancelledAt: tx.cancelledAt ? new Date(tx.cancelledAt) : null,
                inspectionPeriodEnds: tx.inspectionPeriodEnds ? new Date(tx.inspectionPeriodEnds) : null,
                failureReason: tx.failureReason,
                post: tx.postId ? { connect: { id: tx.postId } } : undefined,
                buyer: { connect: { id: buyer.id } },
                seller: { connect: { id: seller.id } },
            }
        });
    }
    console.log("✅ Transactions seeded.");

    // 9. Seed Disputes
    console.log("⚖️ Seeding disputes...");
    for (const d of mockDisputes) {
        const buyer = userMap.get(mockUsers.find(u => u.name === d.buyer)!.username);
        const seller = userMap.get(mockUsers.find(u => u.name === d.seller)!.username);
        if (!buyer || !seller) continue;
        
        await prisma.dispute.create({
            data: {
                id: d.id,
                reason: d.reason,
                status: d.status as DisputeStatus,
                openedDate: new Date(d.openedDate),
                chatHistory: d.chatHistory as unknown as Prisma.JsonValue,
                transaction: { connect: { id: d.transactionId } },
                buyer: { connect: { id: buyer.id } },
                seller: { connect: { id: seller.id } }
            }
        });
    }
    console.log("✅ Disputes seeded.");

    // 10. Seed User Reports
    console.log("🚩 Seeding user reports...");
    for (const report of mockUserReports) {
        await prisma.userReport.create({
            data: {
                id: report.id,
                reason: report.reason,
                details: report.details,
                timestamp: new Date(report.timestamp),
                status: report.status as UserReportStatus,
                reporter: { connect: { id: report.reporterId } },
                reportedUser: { connect: { id: report.reportedUserId } },
            }
        });
    }
    console.log("✅ User reports seeded.");

    console.log("--- Seeding process completed successfully! ---");
}

main()
  .catch((e) => {
    console.error("❌ An error occurred during seeding:");
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });

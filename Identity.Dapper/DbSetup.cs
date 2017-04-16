using Cototal.Dapper.Shared.Standard;
using Dapper;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Identity.Dapper
{
    /// <summary>
    /// Based on Entity Framework Identity implementation schema
    /// </summary>
    public class DbSetup
    {
        private readonly IConnectionFactory _conn;

        public DbSetup(IConnectionFactory conn)
        {
            _conn = conn;
        }

        public void Create()
        {
            using (var db = _conn.Get())
            {
                db.Open();
                using (var trans = db.BeginTransaction())
                {
                    var sql = @"
                        CREATE TABLE [IdentityRole](
                            [Id] [nvarchar](128) NOT NULL,
                            [Name] [nvarchar](256) NOT NULL,
                            CONSTRAINT [PK_IdentityRole_Id] PRIMARY KEY CLUSTERED ([Id] ASC))

                        CREATE TABLE [IdentityUserClaim](
                            [Id] [int] IDENTITY(1,1) NOT NULL,
                            [UserId] [nvarchar](128) NOT NULL,
                            [ClaimType] [nvarchar](max) NULL,
                            [ClaimValue] [nvarchar](max) NULL,
                            CONSTRAINT [PK_IdentityUserClaim_Id] PRIMARY KEY CLUSTERED ([Id] ASC))

                        CREATE TABLE [IdentityUserLogin](
                            [LoginProvider] [nvarchar](128) NOT NULL,
                            [ProviderKey] [nvarchar](128) NOT NULL,
                            [UserId] [nvarchar](128) NOT NULL,
                            CONSTRAINT [PK_IdentityUserLogin_LoginProvider_ProviderKey_userId] PRIMARY KEY CLUSTERED ([LoginProvider] ASC, [ProviderKey] ASC, [UserId] ASC))

                        CREATE TABLE [IdentityUserRole](
                            [UserId] [nvarchar](128) NOT NULL,
                            [RoleId] [nvarchar](128) NOT NULL,
                            CONSTRAINT [PK_IdentityUserRole_UserId_RoleId] PRIMARY KEY CLUSTERED ([UserId] ASC, [RoleId] ASC))

                        CREATE TABLE [IdentityUser](
                            [Id] [nvarchar](128) NOT NULL,
                            [Email] [nvarchar](256) NULL,
                            [EmailConfirmed] [bit] NOT NULL,
                            [PasswordHash] [nvarchar](max) NULL,
                            [SecurityStamp] [nvarchar](max) NULL,
                            [PhoneNumber] [nvarchar](max) NULL,
                            [PhoneNumberConfirmed] [bit] NOT NULL,
                            [TwoFactorEnabled] [bit] NOT NULL,
                            [LockoutEndDateUtc] [datetime] NULL,
                            [LockoutEnabled] [bit] NOT NULL,
                            [AccessFailedCount] [int] NOT NULL,
                            [UserName] [nvarchar](256) NOT NULL,
                            CONSTRAINT [PK_IdentityUser_Id] PRIMARY KEY CLUSTERED ( [Id] ASC))

                        CREATE UNIQUE NONCLUSTERED INDEX [UIX_IdentityRole_Name] ON [IdentityRole] ([Name] ASC)
                        CREATE NONCLUSTERED INDEX [IX_IdentityUserClaim_UserId] ON [IdentityUserClaim] ([UserId] ASC)
                        CREATE NONCLUSTERED INDEX [IX_IdentityUserLogin_UserId] ON [IdentityUserLogin] ([UserId] ASC)
                        CREATE NONCLUSTERED INDEX [IX_IdentityUserRole_RoleId] ON [IdentityUserRole] ([RoleId] ASC)
                        CREATE NONCLUSTERED INDEX [IX_IdentityUserRole_UserId] ON [IdentityUserRole] ([UserId] ASC)
                        CREATE UNIQUE NONCLUSTERED INDEX [UIX_IdentityUser_UserName] ON [IdentityUser] ([UserName] ASC)

                        ALTER TABLE [IdentityUserClaim] ADD CONSTRAINT [FK_IdentityUserClaim.UserId]
                            FOREIGN KEY([UserId]) REFERENCES [IdentityUser] ([Id]) ON DELETE CASCADE
                        ALTER TABLE [IdentityUserLogin] ADD CONSTRAINT [FK_IdentityUserLogin.UserId]
                            FOREIGN KEY([UserId]) REFERENCES [IdentityUser] ([Id]) ON DELETE CASCADE
                        ALTER TABLE [IdentityUserRole]  ADD CONSTRAINT [FK_IdentityUserRole.RoleId]
                            FOREIGN KEY([RoleId]) REFERENCES [IdentityRole] ([Id]) ON DELETE CASCADE
                        ALTER TABLE [IdentityUserRole] ADD CONSTRAINT [FK_IdentityUserRole.UserId]
                            FOREIGN KEY([UserId]) REFERENCES [IdentityUser] ([Id]) ON DELETE CASCADE";
                    db.Execute(sql, transaction: trans);
                    trans.Commit();
                }
            }
        }
        public void Drop()
        {
            using (var db = _conn.Get())
            {
                db.Open();
                using (var trans = db.BeginTransaction())
                {
                    var sql = @"DROP TABLE [IdentityUserClaim];
                        DROP TABLE [IdentityUserLogin];
                        DROP TABLE [IdentityUserRole];
                        DROP TABLE [IdentityRole];
                        DROP TABLE [IdentityUser];";
                    db.Execute(sql, transaction: trans);
                    trans.Commit();
                }
            }
        }
    }
}

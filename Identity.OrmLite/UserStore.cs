using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Claims;
using ServiceStack.Data;
using ServiceStack.OrmLite;

namespace Identity.OrmLite
{
    /// <summary>
    ///     OrmLite based user store implementation that supports IUserStore, IUserLoginStore, IUserClaimStore and
    ///     IUserRoleStore
    ///     Set Methods do not save
    /// </summary>
    public class UserStore : IUserStore<IdentityUser>, IUserLoginStore<IdentityUser>,
        IUserClaimStore<IdentityUser>, IUserRoleStore<IdentityUser>, IUserPasswordStore<IdentityUser>,
        IUserSecurityStampStore<IdentityUser>, IUserEmailStore<IdentityUser>, IUserPhoneNumberStore<IdentityUser>,
        IUserTwoFactorStore<IdentityUser, string>, IUserLockoutStore<IdentityUser, string>
    {
        private readonly IDbConnectionFactory _conn;

        public UserStore(IDbConnectionFactory conn)
        {
            _conn = conn;
        }

        /// <summary>
        ///     Add a claim to a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public async Task AddClaimAsync(IdentityUser user, Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }
            var iuc = new IdentityUserClaim { UserId = user.Id, ClaimType = claim.Type, ClaimValue = claim.Value };
            using (var db = _conn.Open())
            {
                await db.InsertAsync(iuc);
            }
        }

        /// <summary>
        ///     Add a login to the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public async Task AddLoginAsync(IdentityUser user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            var newLogin = new IdentityUserLogin
            {
                UserId = user.Id,
                ProviderKey = login.ProviderKey,
                LoginProvider = login.LoginProvider
            };
            using (var db = _conn.Open())
            {
                await db.InsertAsync(newLogin);
            }
        }

        /// <summary>
        ///     Add a user to a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public async Task AddToRoleAsync(IdentityUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException("roleName");
            }
            using (var db = _conn.Open())
            {
                var role = await db.SingleAsync<IdentityRole>(ir => ir.Name.ToUpper() == roleName.ToUpper());
                if (role == null)
                {
                    throw new InvalidOperationException("role");
                }
                var userRole = new IdentityUserRole { UserId = user.Id, RoleId = role.Id };
                await db.InsertAsync(userRole);
            }
        }


        /// <summary>
        ///     Insert user
        /// </summary>
        /// <param name="user"></param>
        public async Task CreateAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            using (var db = _conn.Open())
            {
                await db.InsertAsync(user);
            }
        }

        /// <summary>
        ///     Delete user
        /// </summary>
        /// <param name="user"></param>
        public async Task DeleteAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            using (var db = _conn.Open())
            {
                await db.DeleteAsync(user);
            }
        }

        public void Dispose()
        {
            // Nothing to dispose?
        }

        /// <summary>
        ///     Returns the user associated with this login
        /// </summary>
        /// <returns></returns>
        public async Task<IdentityUser> FindAsync(UserLoginInfo login)
        {
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            using (var db = _conn.Open())
            {
                var userLogin = await db.SingleAsync<IdentityUserLogin>(
                    iul => iul.LoginProvider == login.LoginProvider
                    && iul.ProviderKey == login.ProviderKey);
                if (userLogin != null)
                {
                    var userId = userLogin.UserId;
                    return await db.SingleByIdAsync<IdentityUser>(userId);
                }
            }
            return null;
        }

        /// <summary>
        ///     Find a user by email
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public async Task<IdentityUser> FindByEmailAsync(string email)
        {
            using (var db = _conn.Open())
            {
                return await db.SingleAsync<IdentityUser>(iu => iu.Email.ToUpper() == email.ToUpper());
            }
        }

        /// <summary>
        ///     Find a user by id
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task<IdentityUser> FindByIdAsync(string userId)
        {
            using (var db = _conn.Open())
            {
                return await db.SingleByIdAsync<IdentityUser>(userId);
            }
        }

        /// <summary>
        ///     Find a user by name
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public async Task<IdentityUser> FindByNameAsync(string userName)
        {
            using (var db = _conn.Open())
            {
                return await db.SingleAsync<IdentityUser>(iu => iu.UserName.ToUpper() == userName.ToUpper());
            }
        }

        /// <summary>
        ///     Returns the current number of failed access attempts.  This number usually will be reset whenever the password is
        ///     verified or the account is locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<int> GetAccessFailedCountAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>
        ///     Return the claims for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task<IList<Claim>> GetClaimsAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            var userClaims = await EnsureUserClaimsAreLoaded(user);
            return userClaims.Select(c => new Claim(c.ClaimType, c.ClaimValue)).ToList();
        }

        /// <summary>
        ///     Get the user's email
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetEmailAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.Email);
        }

        /// <summary>
        ///     Returns whether the user email is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> GetEmailConfirmedAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.EmailConfirmed);
        }

        /// <summary>
        ///     Returns whether the user can be locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> GetLockoutEnabledAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.LockoutEnabled);
        }

        /// <summary>
        ///     Returns the DateTimeOffset that represents the end of a user's lockout, any time in the past should be considered
        ///     not locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<DateTimeOffset> GetLockoutEndDateAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return
                Task.FromResult(user.LockoutEndDateUtc.HasValue
                    ? new DateTimeOffset(DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc))
                    : new DateTimeOffset());
        }

        /// <summary>
        ///     Get the logins for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task<IList<UserLoginInfo>> GetLoginsAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            List<IdentityUserLogin> userLogins;
            if (user.Logins.Count == 0)
            {
                using (var db = _conn.Open())
                {
                    userLogins = await db.SelectAsync<IdentityUserLogin>(iul => iul.UserId == user.Id);
                }
            }
            else
            {
                userLogins = user.Logins;
            }
            return userLogins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey)).ToList();
        }

        /// <summary>
        ///     Get the password hash for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetPasswordHashAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PasswordHash);
        }

        /// <summary>
        ///     Get a user's phone number
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetPhoneNumberAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumber);
        }

        /// <summary>
        ///     Returns whether the user phoneNumber is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        /// <summary>
        ///     Get the names of the roles a user is a member of
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public async Task<IList<string>> GetRolesAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            using (var db = _conn.Open())
            {
                var query = db.From<IdentityRole>()
                    .Join<IdentityUserRole>()
                    .Where<IdentityUserRole>(iur => iur.UserId == user.Id)
                    .Select(ir => ir.Name);

                return await db.ColumnAsync<string>(query);
            }
        }

        /// <summary>
        ///     Get the security stamp for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetSecurityStampAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.SecurityStamp);
        }

        /// <summary>
        ///     Gets whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> GetTwoFactorEnabledAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.TwoFactorEnabled);
        }

        /// <summary>
        ///     Returns true if the user has a password set
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<bool> HasPasswordAsync(IdentityUser user)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        /// <summary>
        ///     Used to record when an attempt to access the user has failed (not saved)
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<int> IncrementAccessFailedCountAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount++;
            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>
        ///     Returns true if the user is in the named role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public async Task<bool> IsInRoleAsync(IdentityUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException("roleName");
            }
            using (var db = _conn.Open())
            {
                var role = await db.SingleAsync<IdentityRole>(ir => ir.Name.ToUpper() == roleName.ToUpper());
                if (role != null)
                {
                    return await db.ExistsAsync<IdentityUserRole>(
                        iur => iur.RoleId == role.Id && iur.UserId == user.Id
                    );
                }
            }
            return false;
        }

        /// <summary>
        ///     Remove a claim from a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public async Task RemoveClaimAsync(IdentityUser user, Claim claim)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (claim == null)
            {
                throw new ArgumentNullException("claim");
            }
            var userClaims = await EnsureUserClaimsAreLoaded(user);
            using (var db = _conn.Open())
            {
                var claimsToRemove = userClaims.Where(
                    uc => uc.ClaimType == claim.Type && uc.ClaimValue == claim.Value
                );
                await db.DeleteByIdsAsync<IdentityUserClaim>(claimsToRemove.Select(iuc => iuc.Id));
            }
        }

        /// <summary>
        ///     Remove a user from a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public async Task RemoveFromRoleAsync(IdentityUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException("roleName");
            }
            var userRoles = await EnsureUserRolesAreLoaded(user);
            if (userRoles.Count == 0)
            {
                return;
            }
            using (var db = _conn.Open())
            {
                var role = await db.SingleAsync<IdentityRole>(ir => ir.Name.ToUpper() == roleName.ToUpper());
                if (role == null)
                {
                    return;
                }
                var userRole = userRoles.SingleOrDefault(ur => ur.RoleId == role.Id);
                if (userRole == null)
                {
                    return;
                }
                await db.DeleteAsync(userRole);
            }
        }

        /// <summary>
        ///     Remove a login from a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public async Task RemoveLoginAsync(IdentityUser user, UserLoginInfo login)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            var userLogins = await EnsureUserLoginsAreLoaded(user);
            if (userLogins.Count == 0)
            {
                return;
            }
            var userLogin = userLogins.SingleOrDefault(
                ul => ul.LoginProvider == login.LoginProvider && ul.ProviderKey == login.ProviderKey
            );
            if (userLogin == null)
            {
                return;
            }
            using (var db = _conn.Open())
            {
                await db.DeleteAsync(userLogin);
            }
        }

        /// <summary>
        ///     Used to reset the account access count, typically after the account is successfully accessed
        ///     (not saved)
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task ResetAccessFailedCountAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.AccessFailedCount = 0;
            return Task.FromResult(0);
        }


        /// <summary>
        ///     Set the user email
        /// </summary>
        /// <param name="user"></param>
        /// <param name="email"></param>
        /// <returns></returns>
        public Task SetEmailAsync(IdentityUser user, string email)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.Email = email;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Set IsConfirmed on the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="confirmed"></param>
        /// <returns></returns>
        public Task SetEmailConfirmedAsync(IdentityUser user, bool confirmed)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.EmailConfirmed = confirmed;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Sets whether the user can be locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public Task SetLockoutEnabledAsync(IdentityUser user, bool enabled)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEnabled = enabled;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Locks a user out until the specified end date (set to a past date, to unlock a user)
        /// </summary>
        /// <param name="user"></param>
        /// <param name="lockoutEnd"></param>
        /// <returns></returns>
        public Task SetLockoutEndDateAsync(IdentityUser user, DateTimeOffset lockoutEnd)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.LockoutEndDateUtc = lockoutEnd == DateTimeOffset.MinValue ? (DateTime?)null : lockoutEnd.UtcDateTime;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Set the password hash for a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="passwordHash"></param>
        /// <returns></returns>
        public Task SetPasswordHashAsync(IdentityUser user, string passwordHash)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Set the user's phone number
        /// </summary>
        /// <param name="user"></param>
        /// <param name="phoneNumber"></param>
        /// <returns></returns>
        public Task SetPhoneNumberAsync(IdentityUser user, string phoneNumber)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.PhoneNumber = phoneNumber;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Returns whether the user phoneNumber is confirmed
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task SetPhoneNumberConfirmedAsync(IdentityUser user, bool confirmed)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        /// <summary>
        ///     Set the security stamp for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="stamp"></param>
        /// <returns></returns>
        public Task SetSecurityStampAsync(IdentityUser user, string stamp)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.SecurityStamp = stamp;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Set whether two factor authentication is enabled for the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="enabled"></param>
        /// <returns></returns>
        public Task SetTwoFactorEnabledAsync(IdentityUser user, bool enabled)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            user.TwoFactorEnabled = enabled;
            return Task.FromResult(0);
        }

        /// <summary>
        ///     Update an entity
        /// </summary>
        /// <param name="user"></param>
        public async Task UpdateAsync(IdentityUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            using (var db = _conn.Open())
            {
                await db.UpdateNonDefaultsAsync(user, iu => iu.Id == user.Id);
            }
        }

        private async Task<List<IdentityUserClaim>> EnsureUserClaimsAreLoaded(IdentityUser user)
        {
            if (user.Claims.Count == 0)
            {
                return await LoadRelationship<IdentityUserClaim>(user);
            }
            return user.Claims;
        }

        private async Task<List<IdentityUserRole>> EnsureUserRolesAreLoaded(IdentityUser user)
        {
            if (user.Roles.Count == 0)
            {
                return await LoadRelationship<IdentityUserRole>(user);
            }
            return user.Roles;
        }

        private async Task<List<IdentityUserLogin>> EnsureUserLoginsAreLoaded(IdentityUser user)
        {
            if (user.Logins.Count == 0)
            {
                return await LoadRelationship<IdentityUserLogin>(user);
            }
            return user.Logins;
        }

        private async Task<List<T>> LoadRelationship<T>(IdentityUser user) where T : IUserRelationship
        {
            using (var db = _conn.Open())
            {
                return await db.SelectAsync<T>(iuc => iuc.UserId == user.Id);
            }
        }
    }
}

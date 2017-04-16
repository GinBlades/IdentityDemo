using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Data.SqlClient;
using Dapper.Contrib.Extensions;
using Dapper;

namespace Identity.Dapper
{
    /// <summary>
    ///     OrmLite based user store implementation that supports IUserStore, IUserLoginStore, IUserClaimStore and
    ///     IUserRoleStore
    ///     Set Methods do not save
    /// </summary>
    public class UserStore<TUser> : IUserStore<TUser>, IUserLoginStore<TUser>,
        IUserClaimStore<TUser>, IUserRoleStore<TUser>, IUserPasswordStore<TUser>,
        IUserSecurityStampStore<TUser>, IUserEmailStore<TUser>, IUserPhoneNumberStore<TUser>,
        IUserTwoFactorStore<TUser, string>, IUserLockoutStore<TUser, string>
        where TUser : IdentityUser
    {
        private readonly SqlConnection _conn;

        public UserStore(SqlConnection conn)
        {
            _conn = conn;
        }

        /// <summary>
        ///     Add a claim to a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public async Task AddClaimAsync(TUser user, Claim claim)
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
            await _conn.InsertAsync(iuc);
        }

        /// <summary>
        ///     Add a login to the user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public async Task AddLoginAsync(TUser user, UserLoginInfo login)
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
            await _conn.InsertAsync(newLogin);
        }

        /// <summary>
        ///     Add a user to a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public async Task AddToRoleAsync(TUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException("roleName");
            }
            var role = await GetRoleByName(roleName);
            if (role == null)
            {
                throw new Exception($"Role ({roleName}) not found");
            }
            var userRole = new IdentityUserRole { UserId = user.Id, RoleId = role.Id };
            await _conn.InsertAsync(userRole);
        }


        /// <summary>
        ///     Insert user
        /// </summary>
        /// <param name="user"></param>
        public async Task CreateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            await _conn.InsertAsync(user);
        }

        /// <summary>
        ///     Delete user
        /// </summary>
        /// <param name="user"></param>
        public async Task DeleteAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            await _conn.DeleteAsync(user);
        }

        public void Dispose()
        {
            // Nothing to dispose?
        }

        /// <summary>
        ///     Returns the user associated with this login
        /// </summary>
        /// <returns></returns>
        public async Task<TUser> FindAsync(UserLoginInfo login)
        {
            if (login == null)
            {
                throw new ArgumentNullException("login");
            }
            var sql = "SELECT * FROM IdentityUserLogin WHERE LoginProvider = @loginProvider " +
                "AND ProviderKey = @providerKey";
            var userLogin = await _conn.QuerySingleOrDefaultAsync<IdentityUserLogin>(
                sql, new { login.LoginProvider, login.ProviderKey });
            if (userLogin != null)
            {
                var userId = userLogin.UserId;
                return await _conn.GetAsync<TUser>(userId);
            }
            return null;
        }

        /// <summary>
        ///     Find a user by email
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        public async Task<TUser> FindByEmailAsync(string email)
        {
            var sql = "SELECT * FROM IdentityUser WHERE lower(email) = @email";
            return await _conn.QuerySingleOrDefaultAsync<TUser>(sql, new { Email = email.ToLower() });
        }

        /// <summary>
        ///     Find a user by id
        /// </summary>
        /// <param name="userId"></param>
        /// <returns></returns>
        public async Task<TUser> FindByIdAsync(string userId)
        {
            return await _conn.GetAsync<TUser>(userId);
        }

        /// <summary>
        ///     Find a user by name
        /// </summary>
        /// <param name="userName"></param>
        /// <returns></returns>
        public async Task<TUser> FindByNameAsync(string userName)
        {
            var sql = "SELECT * FROM IdentityUser WHERE lower(username) = @username";
            return await _conn.QuerySingleOrDefaultAsync<TUser>(sql, new { Username = userName.ToLower() });
        }

        /// <summary>
        ///     Returns the current number of failed access attempts.  This number usually will be reset whenever the password is
        ///     verified or the account is locked out.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<int> GetAccessFailedCountAsync(TUser user)
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
        public async Task<IList<Claim>> GetClaimsAsync(TUser user)
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
        public Task<string> GetEmailAsync(TUser user)
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
        public Task<bool> GetEmailConfirmedAsync(TUser user)
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
        public Task<bool> GetLockoutEnabledAsync(TUser user)
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
        public Task<DateTimeOffset> GetLockoutEndDateAsync(TUser user)
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
        public async Task<IList<UserLoginInfo>> GetLoginsAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            var userLogins = await EnsureUserLoginsAreLoaded(user);
            return userLogins.Select(l => new UserLoginInfo(l.LoginProvider, l.ProviderKey)).ToList();
        }

        /// <summary>
        ///     Get the password hash for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetPasswordHashAsync(TUser user)
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
        public Task<string> GetPhoneNumberAsync(TUser user)
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
        public Task<bool> GetPhoneNumberConfirmedAsync(TUser user)
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
        public async Task<IList<string>> GetRolesAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            var sql = "SELECT Name FROM IdentityRole role " +
                "JOIN IdentityUserRole userRole ON role.Id = userRole.RoleId " +
                "WHERE userRole.UserId = @userId";

            var result = await _conn.QueryAsync<string>(sql, new { UserId = user.Id });
            return result.ToList();
        }

        /// <summary>
        ///     Get the security stamp for a user
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<string> GetSecurityStampAsync(TUser user)
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
        public Task<bool> GetTwoFactorEnabledAsync(TUser user)
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
        public Task<bool> HasPasswordAsync(TUser user)
        {
            return Task.FromResult(user.PasswordHash != null);
        }

        /// <summary>
        ///     Used to record when an attempt to access the user has failed (not saved)
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task<int> IncrementAccessFailedCountAsync(TUser user)
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
        public async Task<bool> IsInRoleAsync(TUser user, string roleName)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (String.IsNullOrWhiteSpace(roleName))
            {
                throw new ArgumentException("roleName");
            }
            var role = await GetRoleByName(roleName);
            if (role != null)
            {
                var existsSql = "SELECT COUNT(1) FROM IdentityUserRole WHERE UserId = @userId AND RoleId = @roleId";
                return await _conn.ExecuteScalarAsync<bool>(existsSql, new { UserId = user.Id, RoleId = role.Id });
            }
            return false;
        }

        /// <summary>
        ///     Remove a claim from a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="claim"></param>
        /// <returns></returns>
        public async Task RemoveClaimAsync(TUser user, Claim claim)
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
            var claimsToRemove = userClaims.Where(
                uc => uc.ClaimType == claim.Type && uc.ClaimValue == claim.Value
            );
            if (claimsToRemove.Count() > 0)
            {
                await _conn.ExecuteAsync(
                    "DELETE FROM IdentityUser Claim WHERE Id IN @Ids", new { Ids = claimsToRemove.Select(c => c.Id) });
            }
        }

        /// <summary>
        ///     Remove a user from a role
        /// </summary>
        /// <param name="user"></param>
        /// <param name="roleName"></param>
        /// <returns></returns>
        public async Task RemoveFromRoleAsync(TUser user, string roleName)
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
            var role = await GetRoleByName(roleName);
            if (role == null)
            {
                return;
            }
            var userRole = userRoles.SingleOrDefault(ur => ur.RoleId == role.Id);
            if (userRole == null)
            {
                return;
            }
            await _conn.DeleteAsync(userRole);
        }

        /// <summary>
        ///     Remove a login from a user
        /// </summary>
        /// <param name="user"></param>
        /// <param name="login"></param>
        /// <returns></returns>
        public async Task RemoveLoginAsync(TUser user, UserLoginInfo login)
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
            await _conn.DeleteAsync(userLogin);
        }

        /// <summary>
        ///     Used to reset the account access count, typically after the account is successfully accessed
        ///     (not saved)
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public Task ResetAccessFailedCountAsync(TUser user)
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
        public Task SetEmailAsync(TUser user, string email)
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
        public Task SetEmailConfirmedAsync(TUser user, bool confirmed)
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
        public Task SetLockoutEnabledAsync(TUser user, bool enabled)
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
        public Task SetLockoutEndDateAsync(TUser user, DateTimeOffset lockoutEnd)
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
        public Task SetPasswordHashAsync(TUser user, string passwordHash)
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
        public Task SetPhoneNumberAsync(TUser user, string phoneNumber)
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
        public Task SetPhoneNumberConfirmedAsync(TUser user, bool confirmed)
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
        public Task SetSecurityStampAsync(TUser user, string stamp)
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
        public Task SetTwoFactorEnabledAsync(TUser user, bool enabled)
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
        public async Task UpdateAsync(TUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            await _conn.UpdateAsync(user);
        }

        private async Task<List<IdentityUserClaim>> EnsureUserClaimsAreLoaded(TUser user)
        {
            if (user.Claims.Count == 0)
            {
                return await LoadRelationship<IdentityUserClaim>(user, "IdentityUserClaim");
            }
            return user.Claims;
        }

        private async Task<List<IdentityUserRole>> EnsureUserRolesAreLoaded(TUser user)
        {
            if (user.Roles.Count == 0)
            {
                return await LoadRelationship<IdentityUserRole>(user, "IdentityUserRole");
            }
            return user.Roles;
        }

        private async Task<List<IdentityUserLogin>> EnsureUserLoginsAreLoaded(TUser user)
        {
            if (user.Logins.Count == 0)
            {
                return await LoadRelationship<IdentityUserLogin>(user, "IdentityUserLogin");
            }
            return user.Logins;
        }

        private async Task<List<T>> LoadRelationship<T>(TUser user, string tableName) where T : IUserRelationship
        {
            var result = await _conn.QueryAsync<T>(
                $"SELECT * FROM {tableName} WHERE UserId = @userId", new { UserId = user.Id });
            return result.ToList();
        }

        private async Task<IdentityRole> GetRoleByName(string roleName)
        {
            var sql = "SELECT * FROM IdentityRole WHERE lower(name) = @roleName";
            return await _conn.QuerySingleOrDefaultAsync<IdentityRole>(sql, new { RoleName = roleName.ToLower() });
        }
    }
}

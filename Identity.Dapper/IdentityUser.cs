using Dapper.Contrib.Extensions;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;

namespace Identity.Dapper
{
    [Table("IdentityUser")]
    public class IdentityUser : IUser
    {
        /// <summary>
        ///     Constructor which creates a new Guid for the Id
        /// </summary>
        public IdentityUser()
        {
            Id = Guid.NewGuid().ToString();
        }

        /// <summary>
        ///     Constructor that takes a userName
        /// </summary>
        /// <param name="userName"></param>
        public IdentityUser(string userName)
            : this()
        {
            UserName = userName;
        }

        /// <summary>
        ///     User ID (Primary Key)
        /// </summary>
        [ExplicitKey]
        public virtual string Id { get; set; }

        /// <summary>
        ///     Email
        /// </summary>
        public virtual string Email { get; set; }

        /// <summary>
        ///     True if the email is confirmed, default is false
        /// </summary>
        public virtual bool EmailConfirmed { get; set; }

        /// <summary>
        ///     The salted/hashed form of the user password
        /// </summary>
        public virtual string PasswordHash { get; set; }

        /// <summary>
        ///     A random value that should change whenever a users credentials have changed (password changed, login removed)
        /// </summary>
        public virtual string SecurityStamp { get; set; }

        /// <summary>
        ///     PhoneNumber for the user
        /// </summary>
        public virtual string PhoneNumber { get; set; }

        /// <summary>
        ///     True if the phone number is confirmed, default is false
        /// </summary>
        public virtual bool PhoneNumberConfirmed { get; set; }

        /// <summary>
        ///     Is two factor enabled for the user
        /// </summary>
        public virtual bool TwoFactorEnabled { get; set; }

        /// <summary>
        ///     DateTime in UTC when lockout ends, any time in the past is considered not locked out.
        /// </summary>
        public virtual DateTime? LockoutEndDateUtc { get; set; }

        /// <summary>
        ///     Is lockout enabled for this user
        /// </summary>
        public virtual bool LockoutEnabled { get; set; }

        /// <summary>
        ///     Used to record failures for the purposes of lockout
        /// </summary>
        public virtual int AccessFailedCount { get; set; }

        /// <summary>
        ///     Navigation property for user roles
        /// </summary>
        [Computed]
        public virtual List<IdentityUserRole> Roles { get; private set; } = new List<IdentityUserRole>();

        /// <summary>
        ///     Navigation property for user claims
        /// </summary>
        [Computed]
        public virtual List<IdentityUserClaim> Claims { get; private set; } = new List<IdentityUserClaim>();

        /// <summary>
        ///     Navigation property for user logins
        /// </summary>
        [Computed]
        public virtual List<IdentityUserLogin> Logins { get; private set; } = new List<IdentityUserLogin>();

        /// <summary>
        ///     User name
        /// </summary>
        public virtual string UserName { get; set; }
    }
}

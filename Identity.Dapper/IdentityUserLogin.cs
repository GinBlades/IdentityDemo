using Dapper.Contrib.Extensions;

namespace Identity.Dapper
{
    /// <summary>
    /// No single primary key, so Dapper.Contrib extensions will not work
    /// </summary>
    [Table("IdentityUserLogin")]
    public class IdentityUserLogin : IUserRelationship
    {
        /// <summary>
        ///     The login provider for the login (i.e. facebook, google)
        /// </summary>
        public virtual string LoginProvider { get; set; }

        /// <summary>
        ///     Key representing the login for the provider
        /// </summary>
        public virtual string ProviderKey { get; set; }

        /// <summary>
        ///     User Id for the user who owns this login
        /// </summary>
        public virtual string UserId { get; set; }
    }
}

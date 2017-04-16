using Dapper.Contrib.Extensions;

namespace Identity.Dapper
{
    /// <summary>
    /// No single primary key, so Dapper.Contrib extensions will not work
    /// </summary>
    [Table("IdentityUserRole")]
    public class IdentityUserRole : IUserRelationship
    {
        /// <summary>
        ///     UserId for the user that is in the role
        /// </summary>
        public virtual string UserId { get; set; }

        /// <summary>
        ///     RoleId for the role
        /// </summary>
        public virtual string RoleId { get; set; }
    }
}

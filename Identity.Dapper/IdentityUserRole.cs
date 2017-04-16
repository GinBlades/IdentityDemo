using Dapper.Contrib.Extensions;

namespace Identity.Dapper
{
    [Table("IdentityUserRole")]
    public class IdentityUserRole : IUserRelationship
    {
        public int Id { get; set; }
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

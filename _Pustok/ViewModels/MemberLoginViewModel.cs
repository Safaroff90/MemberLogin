using System.ComponentModel.DataAnnotations;

namespace _Pustok.ViewModels
{
    public class MemberLoginViewModel
    {
        [MaxLength(25)]
        public string Username { get; set; }
        [MaxLength(20)]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}

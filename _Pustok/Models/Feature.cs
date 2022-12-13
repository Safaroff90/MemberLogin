using System.ComponentModel.DataAnnotations;

namespace _Pustok.Models
{
    public class Feature
    {
        public int Id { get; set; }
        [MaxLength(50)]
        public string Icon { get; set; }
        [MaxLength(50)]
        public string Title { get; set; }
        [MaxLength(100)]
        public string Desc { get; set; }
    }
}

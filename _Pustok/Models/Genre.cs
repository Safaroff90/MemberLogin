using System.ComponentModel.DataAnnotations;

namespace _Pustok.Models
{
    public class Genre
    {
        public int Id { get; set; }
        [MaxLength (100)]
        public string Name { get; set; }
        public List<Book>? Books { get; set; }
        
    }
}

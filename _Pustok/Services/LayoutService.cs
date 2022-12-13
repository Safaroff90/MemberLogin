using _Pustok.DAL;
using _Pustok.Models;

namespace _Pustok.Services
{
    public class LayoutService
    {
        private readonly PustokContext _context;


        public LayoutService(PustokContext context)
        {
            _context = context;
        }

        public Dictionary<string, string> GetSettings()
        {
            return _context.Settings.ToDictionary(x=>x.Key, x => x.Value);
        }

        public List<Genre> GetGenres()
        {
            return _context.Genres.ToList();
        }
    }
}

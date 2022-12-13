namespace _Pustok.Areas.Manage.ViewModels
{
    public class PaginatedList<T> : List<T>
    {
        public int TotalPages { get; }
        public int PageIndex { get; }
        public int PageSize { get; }


        public PaginatedList(List<T> items, int count, int pageIndex, int pageSize)
        {
            this.AddRange(items);
            this.TotalPages = (int)Math.Ceiling(count / (double)pageSize);
            this.PageIndex = pageIndex;
            this.PageSize = pageSize;
        }

        public bool HasNext => PageIndex < TotalPages;
        public bool HasPrevious => PageIndex > 1;

        public static PaginatedList<T> Create(IQueryable<T> query, int pageIndex, int pageSize)
        {
            return new PaginatedList<T>(
                    query.Skip((pageIndex - 1) * pageSize).Take(pageSize).ToList(),
                    query.Count(),
                    pageIndex,
                    pageSize
                );
        }
    }
}

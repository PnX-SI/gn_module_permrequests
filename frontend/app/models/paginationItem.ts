export interface PaginationItem {
  totalItems: number;
  currentPage: number;
  perPage: number;
}

export const DEFAULT_PAGINATION: PaginationItem = {
  totalItems: 0,
  currentPage: 1,
  perPage: 8,
};

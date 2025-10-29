export enum SORT_ORDER {
  ASC = 'asc',
  DESC = 'desc',
}

export interface SortItem {
  sortBy: string;
  sortOrder: SORT_ORDER;
}

export const DEFAULT_SORT: SortItem = {
  sortBy: '',
  sortOrder: SORT_ORDER.ASC,
};

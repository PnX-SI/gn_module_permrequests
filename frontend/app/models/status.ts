export enum STATUS {
  REFUSED = "Refusée",
  PENDING = "Non traitée",
  EXPIRED = "Expirée",
  UPCOMING = "A venir",
  ACTIVE = "Active"
}

export const STATUS_COLORS: Record<STATUS, string> = {
  [STATUS.REFUSED]: "#FF5722",
  [STATUS.PENDING]: "#BDBDBD",
  [STATUS.EXPIRED]: "#FF9800",
  [STATUS.UPCOMING]: "#30a5ff",
  [STATUS.ACTIVE]: "#8BC34A"
}






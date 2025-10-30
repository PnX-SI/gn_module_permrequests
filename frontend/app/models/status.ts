export enum STATUS {
  REFUSED = "REFUSED",
  PENDING = "PENDING",
  EXPIRED = "EXPIRED",
  UPCOMING = "UPCOMING",
  ACTIVE = "ACTIVE"
}

export const STATUS_LABELS: Record<STATUS, string> = {
    [STATUS.REFUSED]: "Refusée",
    [STATUS.PENDING]: "Non traitée",
    [STATUS.EXPIRED]: "Expirée",
    [STATUS.UPCOMING]: "A venir",
    [STATUS.ACTIVE]: "Active",
}

export const STATUS_COLORS: Record<STATUS, string> = {
  [STATUS.REFUSED]: "#FF5722",
  [STATUS.PENDING]: "#BDBDBD",
  [STATUS.EXPIRED]: "#FF9800",
  [STATUS.UPCOMING]: "#30a5ff",
  [STATUS.ACTIVE]: "#8BC34A"
}






export interface AccessRequest {
  id_access_request: number;
  id_author: number;
  id_validator: number | null;
  initialization_date: string | null;
  expiration_date: string | null;
  validated: boolean | null;
  sensitivity_filter: boolean;
  scope: AccessRequestScope | null;
  description: string | null;
  taxa: AccessRequestTaxon[];
  areas: AccessRequestArea[];
  permissions: number[];
  status: string | null;
  author: AccessRequestRole | null;
  validator: AccessRequestRole | null;
  cruved: Cruved | null;
}

export interface AccessRequestRole {
  nom_complet: string | null;
}

export interface AccessRequestTaxon {
  cd_nom: number;
  lb_nom: string;
}

export interface AccessRequestArea {
  id_area: number;
  area_name: string;
  area_code: string | null;
}

export enum AccessRequestScope {
  USER = 'USER',
  ORGANISM = 'ORGANISM',
}

export const DEFAULT_SCOPE = AccessRequestScope.USER;
export interface Cruved {
  C: boolean;
  R: boolean;
  U: boolean;
  V: boolean;
  D: boolean;
}

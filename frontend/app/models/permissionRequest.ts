import { STATUS } from './status';

export interface PermissionRequest {
  id_permission_request: number;
  id_author: number;
  id_validator: number | null;
  created_on: string | null;
  expiration_date: string | null;
  validated: boolean | null;
  sensitivity_filter: boolean;
  scope: PermissionRequestScope | null;
  description: string | null;
  validation_description: string | null;
  taxa: PermissionRequestTaxon[];
  areas: PermissionRequestArea[];
  permissions: number[];
  status: STATUS | null;
  author: PermissionRequestRole | null;
  validator: PermissionRequestRole | null;
  cruved: Cruved | null;
}

export interface PermissionRequestRole {
  nom_complet: string | null;
}

export interface PermissionRequestTaxon {
  cd_nom: number;
  lb_nom: string;
  nom_valide: string | null;
}

export interface PermissionRequestArea {
  id_area: number;
  area_name: string;
  area_code: string | null;
  type_code: string | null;
}

export enum PermissionRequestScope {
  USER = 'USER',
  ORGANISM = 'ORGANISM',
}

export const DEFAULT_SCOPE = PermissionRequestScope.USER;
export interface Cruved {
  C: boolean;
  R: boolean;
  U: boolean;
  V: boolean;
  D: boolean;
}

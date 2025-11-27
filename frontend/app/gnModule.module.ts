import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Routes, RouterModule } from '@angular/router';
import { HttpClientXsrfModule } from '@angular/common/http';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';

import { PermissionRequestService } from './services/permissionRequest.service';
import { ListPageComponent } from './pages/list/list.component';
import { InfoPageComponent } from './pages/info/info.component';
import { NewPageComponent } from './pages/new/new.component';
import { EditPageComponent } from './pages/edit/edit.component';
import { PermissionRequestResolver } from './resolvers/permission-request.resolver';
import { canEditGuard } from './guards/can-edit.guard';
import { canCreateGuard } from './guards/can-create.guard';
import { canViewGuard } from './guards/can-view.guard';

export const ROUTE_PATHS = {
  permissionRequests: '',
  permissionRequest: (id_permission_request: number | string) => `${id_permission_request}`,
  permissionRequestEdit: (id_permission_request: number | string) => `${id_permission_request}/edit`,
  newPermissionRequest: 'new',
};

export const routes: Routes = [
  {
    path: ROUTE_PATHS.permissionRequests,
    component: ListPageComponent,
  },
  {
    path: ROUTE_PATHS.newPermissionRequest,
    component: NewPageComponent,
    canActivate: [canCreateGuard],
  },
  {
    path: ROUTE_PATHS.permissionRequest(':id_permission_request'),
    component: InfoPageComponent,
    resolve: {
      permissionRequest: PermissionRequestResolver,
    },
    canActivate: [canViewGuard],
    runGuardsAndResolvers: 'paramsOrQueryParamsChange',
  },
  {
    path: ROUTE_PATHS.permissionRequestEdit(':id_permission_request'),
    component: EditPageComponent,
    resolve: {
      permissionRequest: PermissionRequestResolver,
    },
    canActivate: [canEditGuard],
    runGuardsAndResolvers: 'paramsOrQueryParamsChange',
  },
];

@NgModule({
  imports: [
    HttpClientXsrfModule.withOptions({
      cookieName: 'token',
      headerName: 'token',
    }),
    CommonModule,
    GN2CommonModule,
    NgbModule,
    RouterModule.forChild(routes),
    // Module pages
    EditPageComponent,
    InfoPageComponent,
    NewPageComponent,
    ListPageComponent,
  ],
  providers: [PermissionRequestService, PermissionRequestResolver],
  bootstrap: [],
})
export class GeonatureModule {}

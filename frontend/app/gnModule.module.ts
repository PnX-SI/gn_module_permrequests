import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Routes, RouterModule } from '@angular/router';
import { HttpClientXsrfModule } from '@angular/common/http';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';

import { AccessRequestService } from './services/accessRequest.service';
import { ListPageComponent } from './pages/list/list.component';
import { AccessRequestInfoPageComponent } from './pages/access-request-info/access-request-info.component';
import { AccessRequestNewPageComponent } from './pages/access-request-new/access-request-new.component';
import { AccessRequestEditPageComponent } from './pages/access-request-edit/access-request-edit.component';
import { AccessRequestResolver } from './resolvers/access-request.resolver';

export const ROUTE_PATHS = {
  accessRequests: '',
  accessRequest: (id_access_request: number | string) => `${id_access_request}`,
  accessRequestEdit: (id_access_request: number | string) => `${id_access_request}/edit`,
  newAccessRequest: 'new',
};

export const routes: Routes = [
  {
    path: ROUTE_PATHS.accessRequests,
    component: ListPageComponent,
  },
  {
    path: ROUTE_PATHS.newAccessRequest,
    component: AccessRequestNewPageComponent,
  },
  {
    path: ROUTE_PATHS.accessRequest(':id_access_request'),
    component: AccessRequestInfoPageComponent,
    resolve: {
      accessRequest: AccessRequestResolver,
    },
  },
  {
    path: ROUTE_PATHS.accessRequestEdit(':id_access_request'),
    component: AccessRequestEditPageComponent,
    resolve: {
      accessRequest: AccessRequestResolver,
    },
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
    AccessRequestEditPageComponent,
    AccessRequestInfoPageComponent,
    AccessRequestNewPageComponent,
    ListPageComponent,
  ],
  providers: [AccessRequestService, AccessRequestResolver],
  bootstrap: [],
})
export class GeonatureModule {}

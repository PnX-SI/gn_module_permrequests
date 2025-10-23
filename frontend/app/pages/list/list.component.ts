import { Component } from '@angular/core';
import { AccessRequestListComponent } from '../../components/access-request-list/access-request-list.component';
import { GN2CommonModule } from '@geonature_common/GN2Common.module';

@Component({
  standalone: true,
  templateUrl: 'list.component.html',
  styleUrls: ['./list.component.scss'],
  providers: [],
  imports: [AccessRequestListComponent, GN2CommonModule],
})
export class ListComponent {}

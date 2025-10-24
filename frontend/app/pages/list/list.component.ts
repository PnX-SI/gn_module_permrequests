import { Component } from '@angular/core';
import { AccessRequestListComponent } from '../../components/access-request-list/access-request-list.component';

@Component({
  standalone: true,
  templateUrl: 'list.component.html',
  styleUrls: ['./list.component.scss'],
  providers: [],
  imports: [AccessRequestListComponent],
})
export class ListPageComponent {}

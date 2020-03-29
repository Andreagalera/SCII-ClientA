import { async, ComponentFixture, TestBed } from '@angular/core/testing';

import { NorepudationComponent } from './norepudation.component';

describe('NorepudationComponent', () => {
  let component: NorepudationComponent;
  let fixture: ComponentFixture<NorepudationComponent>;

  beforeEach(async(() => {
    TestBed.configureTestingModule({
      declarations: [ NorepudationComponent ]
    })
    .compileComponents();
  }));

  beforeEach(() => {
    fixture = TestBed.createComponent(NorepudationComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
